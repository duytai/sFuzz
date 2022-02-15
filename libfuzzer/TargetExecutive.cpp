#include "TargetExecutive.h"
#include "Logger.h"
#include <boost/lexical_cast.hpp>

namespace fuzzer
{
Address ZERO = Address(0);

void TargetExecutive::deploy(bytes data, OnOpFunc onOp)
{
    ca.updateTestData(data);
    program->deploy(addr, bytes{code});
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
}

TargetContainerResult TargetExecutive::execP(pair<bytes /*FuzzData*/, vector<size_t> /*order*/> item,
                                             const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis, bool newOrder,
                                             unordered_set<string> coveredTracebits)
{
    /* Save all hit branches to trace_bits */ 
    Instruction prevInst;
    RecordParam recordParam;
    u256 lastCompValue = 0;
    u256 globalReadWriteEventId = 0;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    double execDur = 0;
    unordered_set<string> uniqExceptions;
    unordered_set<string> tracebits;
    unordered_map<string, u256> predicates;
    vector<ReadWriteNode> trace;
    vector<bytes> outputs;
    size_t savepoint = program->savepoint();
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const *_vm, ExtVMFace const *ext) {
        auto vm = dynamic_cast<LegacyVM const *>(_vm);
        /* Oracle analyze data */
        switch (inst)
        {
        case Instruction::CALL:
        case Instruction::CALLCODE:
        case Instruction::DELEGATECALL:
        case Instruction::STATICCALL:
        {
            vector<u256>::size_type stackSize = vm->stack().size();
            u256 wei = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? vm->stack()[stackSize - 3] : 0;
            auto sizeOffset = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? (stackSize - 4) : (stackSize - 3);
            auto inOff = (uint64_t)vm->stack()[sizeOffset];
            auto inSize = (uint64_t)vm->stack()[sizeOffset - 1];
            auto first = vm->memory().begin();
            OpcodePayload payload;
            payload.caller = ext->myAddress;
            payload.callee = Address((u160)vm->stack()[stackSize - 2]);
            payload.pc = pc;
            payload.gas = vm->stack()[stackSize - 1];
            payload.wei = wei;
            payload.inst = inst;
            payload.data = bytes(first + inOff, first + inOff + inSize);
            oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
            break;
        }
        default:
        {
            OpcodePayload payload;
            payload.pc = pc;
            payload.inst = inst;
            vector<u256>::size_type stackSize = vm->stack().size();
            execDur += timer.elapsed();
            if (inst == Instruction::SSTORE)
            {
                string var = boost::lexical_cast<std::string>(vm->stack()[stackSize - 1]);
                auto node = ReadWriteNode(globalReadWriteEventId++, curSelector, WRITE, var);
                trace.push_back(node);
            }
            if (inst == Instruction::SLOAD)
            {
                string var = boost::lexical_cast<std::string>(vm->stack()[stackSize - 1]);
                auto node = ReadWriteNode(globalReadWriteEventId++, curSelector, READ, var);
                trace.push_back(node);
            }
            execDur -= timer.elapsed();
            //从右向左压入栈
            if (inst == Instruction::SUICIDE || inst == Instruction::NUMBER ||
                inst == Instruction::TIMESTAMP || inst == Instruction::INVALID ||
                inst == Instruction::ADD || inst == Instruction::SUB)
            {
                if (inst == Instruction::ADD || inst == Instruction::SUB)
                {
                    auto left = vm->stack()[stackSize - 1];
                    auto right = vm->stack()[stackSize - 2];
                    if (inst == Instruction::ADD)
                    {
                        auto total256 = left + right;
                        auto total512 = (u512)left + (u512)right;
                        payload.isOverflow = total512 != total256;
                    }
                    if (inst == Instruction::SUB)
                    {
                        payload.isUnderflow = left < right;
                    }
                }
                oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
            }
            break;
        }
        }
        /* Mutation analyzes data */
        switch (inst)
        {
        case Instruction::GT:
        case Instruction::SGT:
        case Instruction::LT:
        case Instruction::SLT:
        case Instruction::EQ:
        {
            vector<u256>::size_type stackSize = vm->stack().size();
            if (stackSize >= 2)
            {
                u256 left = vm->stack()[stackSize - 1];
                u256 right = vm->stack()[stackSize - 2];
                /* calculate if command inside a function */
                u256 temp = left > right ? left - right : right - left;
                lastCompValue = temp + 1;
            }
            break;
        }
        default:
        {
            break;
        }
        }
        /* Calculate left and right branches for valid jumpis*/
        auto recordable = recordParam.isDeployment && get<0>(validJumpis).count(pc);
        recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(pc);
        if (inst == Instruction::JUMPCI && recordable)
        {
            jumpDest1 = (u64)vm->stack().back();
            jumpDest2 = pc + 1;
        }
        /* Calculate actual jumpdest and add reverse branch to predicate */
        recordable = recordParam.isDeployment && get<0>(validJumpis).count(recordParam.lastpc);
        recordable = recordable ||
                     !recordParam.isDeployment && get<1>(validJumpis).count(recordParam.lastpc);
        if (prevInst == Instruction::JUMPCI && recordable)
        { 
            auto branchId = to_string(recordParam.lastpc) + ":" + to_string(pc);
            tracebits.insert(branchId);  
            /* Calculate branch distance */
            u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;
            branchId = to_string(recordParam.lastpc) + ":" +
                       to_string(jumpDest);       
            predicates[branchId] = lastCompValue; // ComValue : |a - b| + 1 
        }
        prevInst = inst;
        recordParam.lastpc = pc;
    };

    vector<bytes> funcs = ca.encodeFunctions(item.first, item.second);
    auto constructor = funcs[0];
    funcs.erase(funcs.begin());
    program->deploy(addr, code);
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    oracleFactory->initialize();
    /* Record all JUMPI in constructor */
    recordParam.isDeployment = true;
    auto sender = ca.getSender();
    OpcodePayload payload;
    payload.inst = Instruction::CALL;
    payload.data = constructor;
    payload.wei = ca.isPayable("") ? program->getBalance(sender) / 2 : 0;
    payload.caller = sender;
    payload.callee = addr;
    oracleFactory->save(OpcodeContext(0, payload));
    double t = timer.elapsed();
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, constructor, ca.isPayable(""), onOp);
    execDur += timer.elapsed() - t;
    if (res.excepted != TransactionException::None)
    {
        auto exceptionId = to_string(recordParam.lastpc);
        uniqExceptions.insert(exceptionId);
        /* Save Call Log */
        OpcodePayload payload;
        payload.inst = Instruction::INVALID;
        oracleFactory->save(OpcodeContext(0, payload));
    }
    oracleFactory->finalize();
    /* Decode and call functions */
    vector<size_t> order = item.second;
    vector<FuncDef> fds;
    for (uint32_t i = 0; i < order.size(); i++)
    {
        auto fd = ca.fds[order[i]];
        fds.push_back(fd);
    }
    
    for (size_t i = 0; i < fds.size(); i++)
    {
        auto fd = fds[i];
        curSelector = fd.selector;
        auto func = funcs[i];
        // cout << fd.name << " " << toHex(func) << endl;
        /* Ignore JUMPI until program reaches inside function */
        recordParam.isDeployment = false;
        OpcodePayload payload;
        payload.data = func;
        payload.inst = Instruction::CALL;
        payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
        payload.caller = sender;
        payload.callee = addr;
        oracleFactory->save(OpcodeContext(0, payload));
        t = timer.elapsed();
        res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
        execDur += timer.elapsed() - t;
        outputs.push_back(res.output);
        if (res.excepted != TransactionException::None)
        {
            auto exceptionId = to_string(recordParam.lastpc);
            uniqExceptions.insert(exceptionId);
            /* Save Call Log */
            OpcodePayload payload;
            payload.inst = Instruction::INVALID;
            oracleFactory->save(OpcodeContext(0, payload));
        }
        oracleFactory->finalize();
    }

    vector<Pattern *> patterns;
    // If newOrder or newBranch covered then we try to match new Pattern
    bool newBranch = false;
    unordered_set<string> newTracebits;
    for (auto tracebit : tracebits)
    {
        if (!coveredTracebits.count(tracebit))
        {
            newTracebits.insert(tracebit);
        }
    }
    if (newOrder || !newTracebits.size())
    {
        patterns = getAllPatterns(trace);
    }
    /* Reset data before running new contract */
    program->rollback(savepoint);
    string cksum = "";
    vector<tuple<bool /*isCostructor*/, uint32_t, bytes, unordered_set<string>, vector<ReadWriteNode>>> funcsExec;
    for (auto t : tracebits)
        cksum = cksum + t;
    return TargetContainerResult(newTracebits, predicates, uniqExceptions, cksum, patterns, funcsExec, execDur);
}

TargetContainerResult TargetExecutive::execA(pair<bytes /*FuzzData*/, vector<size_t> /*order*/> item,
                                             const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis, bool newOrder,
                                             unordered_set<string> coveredTracebits)
{
    /* Save all hit branches to trace_bits */ 
    Instruction prevInst;
    RecordParam recordParam;
    u256 lastCompValue = 0;
    u256 globalReadWriteEventId = 0;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    double execDur = 0;
    unordered_set<string> uniqExceptions;
    unordered_set<string> tracebits;
    unordered_map<string, u256> predicates;
    vector<ReadWriteNode> trace;
    vector<tuple<bool /*isCostructor*/, uint32_t, bytes, unordered_set<string>, vector<ReadWriteNode>>> funcsExec;
    unordered_set<string> vars;
    vector<ReadWriteNode> funcTrace;

    vector<bytes> outputs;
    size_t savepoint = program->savepoint();
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const *_vm, ExtVMFace const *ext) {
        auto vm = dynamic_cast<LegacyVM const *>(_vm);
        /* Oracle analyze data */
        switch (inst)
        {
        case Instruction::CALL:
        case Instruction::CALLCODE:
        case Instruction::DELEGATECALL:
        case Instruction::STATICCALL:
        {
            vector<u256>::size_type stackSize = vm->stack().size();
            u256 wei = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? vm->stack()[stackSize - 3] : 0;
            auto sizeOffset = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? (stackSize - 4) : (stackSize - 3);
            auto inOff = (uint64_t)vm->stack()[sizeOffset];
            auto inSize = (uint64_t)vm->stack()[sizeOffset - 1];
            auto first = vm->memory().begin();
            OpcodePayload payload;
            payload.caller = ext->myAddress;
            payload.callee = Address((u160)vm->stack()[stackSize - 2]);
            payload.pc = pc;
            payload.gas = vm->stack()[stackSize - 1];
            payload.wei = wei;
            payload.inst = inst;
            payload.data = bytes(first + inOff, first + inOff + inSize);
            oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
            break;
        }
        default:
        {
            OpcodePayload payload;
            payload.pc = pc;
            payload.inst = inst;
            vector<u256>::size_type stackSize = vm->stack().size();
            execDur += timer.elapsed();
            if (inst == Instruction::SSTORE)
            {
                string var = boost::lexical_cast<std::string>(vm->stack()[stackSize - 1]);
                auto node = ReadWriteNode(globalReadWriteEventId++, curSelector, WRITE, var);
                funcTrace.push_back(node);
                vars.insert(var);
                trace.push_back(node);
            }
            if (inst == Instruction::SLOAD)
            {
                string var = boost::lexical_cast<std::string>(vm->stack()[stackSize - 1]);
                auto node = ReadWriteNode(globalReadWriteEventId++, curSelector, READ, var);
                funcTrace.push_back(node);
                vars.insert(var);
                trace.push_back(node);
            }
            execDur -= timer.elapsed(); 
            if (inst == Instruction::SUICIDE || inst == Instruction::NUMBER ||
                inst == Instruction::TIMESTAMP || inst == Instruction::INVALID ||
                inst == Instruction::ADD || inst == Instruction::SUB)
            {
                if (inst == Instruction::ADD || inst == Instruction::SUB)
                {
                    auto left = vm->stack()[stackSize - 1];
                    auto right = vm->stack()[stackSize - 2];
                    if (inst == Instruction::ADD)
                    {
                        auto total256 = left + right;
                        auto total512 = (u512)left + (u512)right;
                        payload.isOverflow = total512 != total256;
                    }
                    if (inst == Instruction::SUB)
                    {
                        payload.isUnderflow = left < right;
                    }
                }
                oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
            }
            break;
        }
        }
        /* Mutation analyzes data */
        switch (inst)
        {
        case Instruction::GT:
        case Instruction::SGT:
        case Instruction::LT:
        case Instruction::SLT:
        case Instruction::EQ:
        {
            vector<u256>::size_type stackSize = vm->stack().size();
            if (stackSize >= 2)
            {
                u256 left = vm->stack()[stackSize - 1];
                u256 right = vm->stack()[stackSize - 2];
                /* calculate if command inside a function */
                u256 temp = left > right ? left - right : right - left;
                lastCompValue = temp + 1;
            }
            break;
        }
        default:
        {
            break;
        }
        }
        /* Calculate left and right branches for valid jumpis*/
        auto recordable = recordParam.isDeployment && get<0>(validJumpis).count(pc);
        recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(pc);
        if (inst == Instruction::JUMPCI && recordable)
        {
            jumpDest1 = (u64)vm->stack().back();
            jumpDest2 = pc + 1;
        }
        /* Calculate actual jumpdest and add reverse branch to predicate */
        recordable = recordParam.isDeployment && get<0>(validJumpis).count(recordParam.lastpc);
        recordable = recordable ||
                     !recordParam.isDeployment && get<1>(validJumpis).count(recordParam.lastpc);
        if (prevInst == Instruction::JUMPCI && recordable)
        { 
            auto branchId = to_string(recordParam.lastpc) + ":" + to_string(pc);
            tracebits.insert(branchId); 
            /* Calculate branch distance */
            u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;
            branchId = to_string(recordParam.lastpc) + ":" +
                       to_string(jumpDest);      
            predicates[branchId] = lastCompValue; 
        }
        prevInst = inst;
        recordParam.lastpc = pc;
    };

    vector<bytes> funcs = ca.encodeFunctions(item.first, item.second);
    auto constructor = funcs[0];
    funcs.erase(funcs.begin());
    program->deploy(addr, code);
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    oracleFactory->initialize();
    /* Record all JUMPI in constructor */
    recordParam.isDeployment = true;
    auto sender = ca.getSender();
    OpcodePayload payload;
    payload.inst = Instruction::CALL;
    payload.data = constructor;
    payload.wei = ca.isPayable("") ? program->getBalance(sender) / 2 : 0;
    payload.caller = sender;
    payload.callee = addr;
    oracleFactory->save(OpcodeContext(0, payload));
    double t = timer.elapsed();
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, constructor, ca.isPayable(""), onOp);
    execDur += timer.elapsed() - t;
    if (res.excepted != TransactionException::None)
    {
        auto exceptionId = to_string(recordParam.lastpc);
        uniqExceptions.insert(exceptionId);
        /* Save Call Log */
        OpcodePayload payload;
        payload.inst = Instruction::INVALID;
        oracleFactory->save(OpcodeContext(0, payload));
    }
    funcsExec.push_back(make_tuple(
        true, 0, constructor, unordered_set<string>(vars), vector<ReadWriteNode>(funcTrace)));
    oracleFactory->finalize();
    /* Decode and call functions */
    
    vector<size_t> order = item.second;
    vector<FuncDef> fds;

    for (uint32_t i = 0; i < order.size(); i++)
    {
        auto fd = ca.fds[order[i]];
        fds.push_back(fd);
    }
    for (size_t i = 0; i < fds.size(); i++)
    {
        vars.clear();
        funcTrace.clear();
        auto fd = fds[i];
        curSelector = fd.selector;
        auto func = funcs[i];
        // cout << fd.name << " " << toHex(func) << endl;
        /* Ignore JUMPI until program reaches inside function */
        recordParam.isDeployment = false;
        OpcodePayload payload;
        payload.data = func;
        payload.inst = Instruction::CALL;
        payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
        payload.caller = sender;
        payload.callee = addr;
        oracleFactory->save(OpcodeContext(0, payload));
        t = timer.elapsed();
        res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
        execDur += timer.elapsed() - t;
        outputs.push_back(res.output);
        if (res.excepted != TransactionException::None)
        {
            auto exceptionId = to_string(recordParam.lastpc);
            uniqExceptions.insert(exceptionId);
            /* Save Call Log */
            OpcodePayload payload;
            payload.inst = Instruction::INVALID;
            oracleFactory->save(OpcodeContext(0, payload));
        }
        funcsExec.push_back(make_tuple(false, fd.selector, func, unordered_set<string>(vars), vector<ReadWriteNode>(funcTrace)));
        oracleFactory->finalize();
    }

    vector<Pattern*> patterns;
    // If newOrder or newBranch covered then we try to match new Pattern
    bool newBranch = false;
    unordered_set<string> newTracebits;
    for (auto tracebit : tracebits)
    {
        if (!coveredTracebits.count(tracebit))
        {
            newTracebits.insert(tracebit);
        }
    }
    if (newOrder || !newTracebits.size())
    {
        patterns = getAllPatterns(trace);
    }
    /* Reset data before running new contract */
    program->rollback(savepoint);
    string cksum = "";
    for (auto t : tracebits)
        cksum = cksum + t;
    return TargetContainerResult(newTracebits, predicates, uniqExceptions, cksum, patterns, funcsExec, execDur);
}

} // namespace fuzzer

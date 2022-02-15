#include "ContractABI.h"

namespace fuzzer
{
using EventType = string;
const EventType READ = "Read";
const EventType WRITE = "Write";

struct ReadWriteNode
{
    /* data */
    long GID;
    uint32_t selector;  //
    EventType type;         // READ or WRITE
    string var;               // var identifier
    string funcName;          // 
    ReadWriteNode(uint32_t selector, EventType type, string var)
      : GID(0), selector(selector), type(type), var(var){};
    ReadWriteNode(u256 GID, uint32_t selector, EventType type, string var)
      : GID(GID), selector(selector), type(type), var(var){};
};

struct Pattern
{
    vector<ReadWriteNode> nodes;
    string patternType;
    Pattern(vector<ReadWriteNode> nodes) : nodes(nodes)
    {
        if (nodes.size() == 2 || nodes.size() == 3)
        {
            patternType = "";
            for (auto node : nodes)
            {
                if (node.type == READ)
                {
                    patternType += "R";
                }
                else if (node.type == WRITE)
                {
                    patternType += "W";
                }
            } 
        }
        // len为4的Patterntype另行设置
    }
};

inline std::ostream& operator<<(std::ostream& _out, ReadWriteNode rw)
{
    _out << rw.type << "Node: [ GID: " << rw.GID << ", selector: " << rw.selector
         << ", var: " << rw.var << " ]" << endl;
    return _out;
}

inline std::ostream& operator<<(std::ostream& _out, Pattern* pattern)
{
    _out << "Pattern { " << endl;
    for (auto node : pattern->nodes)
    {
        _out << "    ";
        _out << node.type << "Node: [ GID: " << node.GID << ", selector: " << node.selector
             << ", var: " << node.var << " ]" << endl;
    }
    _out << "}" << endl;
    return _out;
}

}  // namespace fuzzer
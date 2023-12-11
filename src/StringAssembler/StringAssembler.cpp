#include "../StringAssembler.h"

void StringAssembler::insertString(size_t idx, const std::string s){
    std::unique_lock<std::mutex> lock(mtx);
    totalStringLength += s.size();
    if (idx < data.size()) {
        data[idx] = s;
    }
}

StringAssembler::StringAssembler(size_t sz){
    data.resize(sz);
}

std::string StringAssembler::assembleFinalString(){
    std::string ret; ret.reserve(totalStringLength);

    for(const auto& s : data){
        ret += s;
    }

    return ret;
}
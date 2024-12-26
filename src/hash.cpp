#pragma once
#include "hash.h"
#include "string"

unsigned long calcHash(std::string name ) {
    unsigned long hash = 5000;
    int c=0;

    while (c < name.length()) {
        hash = ((hash << 5) + hash) + name[c];
        c += 1;
    }

    return hash;
}
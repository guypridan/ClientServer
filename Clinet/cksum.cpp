#include "cksum.h"

unsigned long memcrc(char* b, size_t n)
{
    unsigned int v = 0, c = 0;
    unsigned long s = 0;
    unsigned int tabidx;

    for (int i = 0; i < n; i++) {
        tabidx = (s >> 24) ^ (unsigned char)b[i];
        s = UNSIGNED((s << 8)) ^ crctab[0][tabidx];
    }

    while (n) {
        c = n & 0377;
        n = n >> 8;
        s = UNSIGNED(s << 8) ^ crctab[0][(s >> 24) ^ c];
    }
    return (unsigned long)UNSIGNED(~s);
}


unsigned long cksum(std::string fname)
{
    if (std::filesystem::exists(fname)) {
        std::filesystem::path fpath = fname;
        std::ifstream f1(fname.c_str(), std::ios::binary);

        size_t size = std::filesystem::file_size(fpath);
        char* b = new char[size];
        f1.seekg(0, std::ios::beg);
        f1.read(b, size);
        unsigned long ret = memcrc(b, size);

        delete[] b;
        return ret;
    }
    return 0;
}
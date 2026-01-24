#ifndef __DEBUG_HH__
#define __DEBUG_HH__

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include "op.hh"

namespace ghidra {
  static FILE *segdbg_fp(void) {
    static FILE *fp = (FILE *)-1;
    if (fp != (FILE *)-1) return fp;

    const char *path = getenv("SEGDBG_LOG");
    if (path == NULL || *path == '\0') path = "/tmp/segdbg.log";

    fp = fopen(path, "a");
    if (fp == NULL) fp = stderr;          // fallback (manual runs)
    setvbuf(fp, NULL, _IOLBF, 0);          // line buffered
    return fp;
  }

#define SEGDBG(fmt, ...) do { \
  break; \
  FILE *fp = segdbg_fp(); \
  fprintf(fp, "[segdbg] " fmt "\n", ##__VA_ARGS__); \
  fflush(fp); \
} while (0)

static inline std::string segdbg_pcodeop(const PcodeOp *op)
{
    if (op == nullptr) {
        return "<null PcodeOp>";
    }

    std::ostringstream oss;
    op->printDebug(oss);

    return oss.str();
}

static inline std::string segdbg_datatype(const Datatype *dt)
{
    if (dt == nullptr) {
        return "<null DataType>";
    }

    std::ostringstream oss;
    dt->printRaw(oss);

    return oss.str();
}
static inline std::string segdbg_symbol(const Symbol *sym) {
  std::ostringstream oss;

  if (sym == (const Symbol*)0) {
    return oss.str();
  }

  oss << sym->getName();
  return oss.str();
}

static inline std::string segdbg_varnode(const Varnode *vn)
{
    if (vn == nullptr) {
        return "<null Varnode>";
    }
    
    std::ostringstream oss;
    oss << "\nvn: ";
    vn->printInfo(oss);
    oss << "size: " << vn->getSize() << ", space: " << vn->getSpace()->getName();
    if (vn->getSymbolEntry() != (const SymbolEntry*)0) {
      oss << "\nsymbol: ";
      vn->getSymbolEntry()->printEntry(oss);
    }  
    if (vn->getHigh() != (const HighVariable*)0) {
      oss << "\nhigh variable: ";
      vn->getHigh()->printInfo(oss);
    }
    oss << "\n";

    return oss.str();
}

static inline std::string segdb_atom(const PrintLanguage::Atom &atom)
{
    using tagtype = PrintLanguage::tagtype;
    std::ostringstream oss;

    switch (atom.type) {
    // Replace these with the actual tagtype values in your tree:
    case PrintLanguage::tagtype::vartoken:
        oss << atom.name << " vn: " << segdbg_varnode(atom.ptr_second.vn);
        return oss.str();

    default:
        return atom.name;
    }
}

}

#endif
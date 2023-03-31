//==============================================================================
// FILE:
//    MismatchMallocChecker.cpp
//
// DESCRIPTION:
//    Check if a pointer is allocated by malloc() and freed by pfree().
//    or allocated by palloc() and freed by free().
//
// USAGE:
//   clang -cc1 -load libMimatchMallocChecker.so -analyze '\'
//     -analyzer-checker=alpha.postgres.MismatchMallocChecker
//
//==============================================================================
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include <clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h>
#include <llvm/Support/Casting.h>
#include <utility>

using namespace clang;
using namespace ento;

namespace {
typedef SmallVector<SymbolRef, 2> SymbolVector;

struct AllocState {
private:
  enum Kind { Malloc, Free, Palloc, Pfree } K;
  AllocState(Kind InK) : K(InK) {}

public:
  bool isMallocated() const { return K == Malloc; }
  bool isFreed() const { return K == Free; }
  bool isPallocated() const { return K == Palloc; }
  bool isPfreed() const { return K == Pfree; }

  static AllocState getMallocated() { return AllocState(Malloc); }
  static AllocState getFreed() { return AllocState(Free); }
  static AllocState getPallocated() { return AllocState(Palloc); }
  static AllocState getPfreed() { return AllocState(Pfree); }

  bool operator==(const AllocState &X) const { return K == X.K; }
  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(K); }
};

class MismatchMallocChecker : public Checker<check::PostCall, check::PreCall> {
  CallDescription MallocFn, FreeFn, PallocFn, Palloc0Fn, PfreeFn;
  std::unique_ptr<BugType> MismatchAllocBugType;

  void reportInconsistentMalloc(SymbolRef AllocatedPtr, const CallEvent &Call,
                                CheckerContext &C) const;

public:
  MismatchMallocChecker();

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

/// The state of the checker is a map from tracked stream symbols to their
/// state. Let's store it in the ProgramState.
REGISTER_MAP_WITH_PROGRAMSTATE(AllocMap, SymbolRef, AllocState)

MismatchMallocChecker::MismatchMallocChecker()
    : MallocFn({"malloc"}), FreeFn({"free"}), PallocFn({"palloc"}),
      Palloc0Fn({"palloc0"}), PfreeFn({"pfree"}) {
  // Initialize the bug types.
  MismatchAllocBugType.reset(
      new BugType(this, "Mismatched malloc()/palloc()/free()/pfree()",
                  "Postgres API Error"));
}

void MismatchMallocChecker::checkPostCall(const CallEvent &Call,
                                          CheckerContext &C) const {
  if (!Call.isGlobalCFunction())
    return;

  if (MallocFn.matches(Call)) {
    // Get the symbolic value corresponding to the file handle.
    SymbolRef AllocatedPtr = Call.getReturnValue().getAsSymbol();
    if (!AllocatedPtr)
      return;

    // Generate the next transition (an edge in the exploded graph).
    ProgramStateRef State = C.getState();
    State = State->set<AllocMap>(AllocatedPtr, AllocState::getMallocated());
    C.addTransition(State);
  } else if (PallocFn.matches(Call) || Palloc0Fn.matches(Call)) {
    // Get the symbolic value corresponding to the file handle.
    SymbolRef PallocatedPtr = Call.getReturnValue().getAsSymbol();
    if (!PallocatedPtr)
      return;

    // Generate the next transition (an edge in the exploded graph).
    ProgramStateRef State = C.getState();
    State = State->set<AllocMap>(PallocatedPtr, AllocState::getPallocated());
    C.addTransition(State);
  }
}

void MismatchMallocChecker::checkPreCall(const CallEvent &Call,
                                         CheckerContext &C) const {
  if (!Call.isGlobalCFunction())
    return;

  if (FreeFn.matches(Call)) {
    SymbolRef AllocatedPtr = Call.getArgSVal(0).getAsSymbol();
    if (!AllocatedPtr)
      return;

    // Check if the pointer is created by palloc().
    ProgramStateRef State = C.getState();
    const AllocState *AS = State->get<AllocMap>(AllocatedPtr);
    if (AS && AS->isPallocated()) {
      reportInconsistentMalloc(AllocatedPtr, Call, C);
    }

    State = State->set<AllocMap>(AllocatedPtr, AllocState::getFreed());
  } else if (PfreeFn.matches(Call)) {
    SymbolRef AllocatedPtr = Call.getArgSVal(0).getAsSymbol();
    if (!AllocatedPtr)
      return;

    // Check if the pointer is created by malloc().
    ProgramStateRef State = C.getState();
    const AllocState *AS = State->get<AllocMap>(AllocatedPtr);
    if (AS && AS->isMallocated()) {
      reportInconsistentMalloc(AllocatedPtr, Call, C);
    }

    State = State->set<AllocMap>(AllocatedPtr, AllocState::getPfreed());
  }
}

void MismatchMallocChecker::reportInconsistentMalloc(SymbolRef AllocatedPointer,
                                                     const CallEvent &Call,
                                                     CheckerContext &C) const {
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;

  // Generate the report.
  auto R = std::make_unique<PathSensitiveBugReport>(
      *MismatchAllocBugType,
      "Freeing a malloc() memory with pfree() or freeing a palloc() memory"
      "with free()",
      ErrNode);
  R->addRange(Call.getSourceRange());
  R->markInteresting(AllocatedPointer);
  C.emitReport(std::move(R));
}

//-----------------------------------------------------------------------------
// Registration
//-----------------------------------------------------------------------------
// See clang/StaticAnalyzer/Core/CheckerRegistry.h for details on  creating
// plugins for the clang static analyzer. The requirements are that each
// plugin include the version string and registry function below. The checker
// should then be usable with:
//
//   clang -cc1 -load </path/to/plugin> -analyze '\'
//     -analyzer-checker=<prefix.checkername>
//
// You can double check that it is working/found by listing the available
// checkers with the -analyzer-checker-help option.
extern "C" __attribute__((visibility("default")))
const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" __attribute__((visibility("default"))) void
clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<MismatchMallocChecker>(
      /*FullName=*/"alpha.postgres.MismatchMallocChecker",
      /*Desc=*/
      "Find memory allocated or freed by mismatched "
      "malloc()/palloc()/free()/pfree()",
      /*DocsUri=*/"");
}

//==============================================================================
// FILE:
//    ListFreeChecker.cpp
//
// DESCRIPTION:
//    Check if a (List *) pointer is freed by pfree().
//
// USAGE:
//   clang -cc1 -load libListFreeChecker.so -analyze '\'
//     -analyzer-checker=alpha.postgres.ListFreeChecker
//
//==============================================================================
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include <llvm/Support/Casting.h>
#include <utility>

using namespace clang;
using namespace ento;

namespace {
class SimpleListFreeChecker : public Checker<check::PreCall> {
  CallDescription FreeFn;
  std::unique_ptr<BugType> FreeListWithPFreeBugType;

  void reportInconsistentListFree(SymbolRef FileDescSym, const CallEvent &Call,
                                  CheckerContext &C) const;

public:
  SimpleListFreeChecker();
  /// Process pfree.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

SimpleListFreeChecker::SimpleListFreeChecker() : FreeFn({"pfree"}) {
  // Initialize the bug types.
  FreeListWithPFreeBugType.reset(
      new BugType(this, "Applying pfree() on a list", "Postgres API Error"));
}

void SimpleListFreeChecker::checkPreCall(const CallEvent &Call,
                                         CheckerContext &C) const {
  if (!Call.isGlobalCFunction() || !FreeFn.matches(Call))
    return;

  // Suppress warnings in list_free_private().
  if (auto LC = C.getLocationContext()) {
    if (auto Decl = llvm::dyn_cast_or_null<FunctionDecl>(LC->getDecl())) {
      if (Decl->getName() == "list_free_private")
        return;
    }
  }

  // Get the symbolic value corresponding to the list pointer.
  SymbolRef ListPointer = Call.getArgSVal(0).getAsSymbol();
  if (!ListPointer)
    return;

  // Check if the type of pfree() argument is List *.
  QualType PointerType = ListPointer->getType();
  if (PointerType.isNull())
    return;

  std::string TyName =
      PointerType->getPointeeType().getUnqualifiedType().getAsString();
  if (TyName == "List")
    reportInconsistentListFree(ListPointer, Call, C);
}

void SimpleListFreeChecker::reportInconsistentListFree(
    SymbolRef ListPointer, const CallEvent &Call, CheckerContext &C) const {
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;

  // Generate the report.
  auto R = std::make_unique<PathSensitiveBugReport>(
      *FreeListWithPFreeBugType, "Freeing a (List *) with pfree()", ErrNode);
  R->addRange(Call.getSourceRange());
  R->markInteresting(ListPointer);
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
const char clang_analyzerAPIVersionString[] = "16.0.0";

extern "C" __attribute__((visibility("default"))) void
clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SimpleListFreeChecker>(
      /*FullName=*/"alpha.postgres.ListFreeChecker",
      /*Desc=*/"Find (List *) freed by pfree()",
      /*DocsUri=*/"");
}

#include "CatchMissingFlushOrRethrowCheck.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {
namespace {

const BinaryOperator *asAssignment(const Stmt *S) {
  const auto *E = dyn_cast<Expr>(S);
  if (!E)
    return nullptr;
  const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
  if (!BO || !BO->isAssignmentOp())
    return nullptr;
  return BO;
}

// PG_FINALLY's else is `_do_rethrow… = true`, not a CATCH body.
bool isDoRethrowAssign(const Stmt *S) {
  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    if (CS->size() != 1)
      return false;
    S = *CS->body_begin();
  }
  const BinaryOperator *BO = asAssignment(S);
  if (!BO)
    return false;
  const auto *DRE =
      dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts());
  return DRE && DRE->getDecl()->getName().starts_with("_do_rethrow");
}

// Canonical elog.c APIs that pop or propagate the current errordata slot.
// Cross-TU PL helpers (PLy_spi_subtransaction_abort, pltcl_subtrans_abort)
// CopyErrorData+FlushErrorState; match them by the usual name shape when
// their bodies are not in this TU. ereport/elog are not handlers.
bool isErrorStackHandlerName(StringRef Name) {
  if (Name == "FlushErrorState" || Name == "pg_re_throw" ||
      Name == "ReThrowError")
    return true;
  return Name.contains("subtrans_abort") ||
         Name.contains("subtransaction_abort");
}

bool stmtHandlesError(const Stmt *S,
                      llvm::SmallPtrSet<const FunctionDecl *, 8> &Seen,
                      unsigned Depth);

class CallCollector : public RecursiveASTVisitor<CallCollector> {
  llvm::SmallVector<const CallExpr *, 8> &Calls;

public:
  explicit CallCollector(llvm::SmallVector<const CallExpr *, 8> &Calls)
      : Calls(Calls) {}

  bool VisitCallExpr(CallExpr *CE) {
    Calls.push_back(CE);
    return true;
  }
};

bool stmtHandlesError(const Stmt *S,
                      llvm::SmallPtrSet<const FunctionDecl *, 8> &Seen,
                      unsigned Depth) {
  if (!S || Depth > 8)
    return false;

  llvm::SmallVector<const CallExpr *, 8> Calls;
  CallCollector Collector(Calls);
  Collector.TraverseStmt(const_cast<Stmt *>(S));

  llvm::SmallVector<const Stmt *, 4> CalleeBodies;
  for (const CallExpr *CE : Calls) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      continue;
    FD = FD->getCanonicalDecl();
    if (isErrorStackHandlerName(FD->getName()))
      return true;
    const FunctionDecl *Def = FD->getDefinition();
    if (!Def || !Def->hasBody() || !Seen.insert(Def).second)
      continue;
    CalleeBodies.push_back(Def->getBody());
  }
  for (const Stmt *Body : CalleeBodies) {
    if (stmtHandlesError(Body, Seen, Depth + 1))
      return true;
  }
  return false;
}

bool catchHandlesError(const Stmt *Catch) {
  llvm::SmallPtrSet<const FunctionDecl *, 8> Seen;
  return stmtHandlesError(Catch, Seen, 0);
}

} // namespace

void CatchMissingFlushOrRethrowCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      ifStmt(hasCondition(binaryOperator(
                 hasOperatorName("=="),
                 hasOperands(callExpr(callee(functionDecl(hasName("__sigsetjmp")))),
                             integerLiteral(equals(0))))))
          .bind("pg_try"),
      this);
}

void CatchMissingFlushOrRethrowCheck::check(
    const MatchFinder::MatchResult &Result) {
  const auto *If = Result.Nodes.getNodeAs<IfStmt>("pg_try");
  if (!If)
    return;

  const Stmt *Else = If->getElse();
  if (!Else || isDoRethrowAssign(Else))
    return;

  if (catchHandlesError(Else))
    return;

  diag(Else->getBeginLoc(),
       "PG_CATCH block neither flushes nor rethrows the error; call "
       "FlushErrorState(), PG_RE_THROW(), or ReThrowError() so the errordata "
       "stack is not leaked");
}

} // namespace postgres
} // namespace tidy
} // namespace clang

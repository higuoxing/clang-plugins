#include "DiscardedListOrBmsResultCheck.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "llvm/ADT/StringSwitch.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {
namespace {

// Functions that recycle (modify, repalloc, or free) a List * / Bitmapset *
// argument and return the possibly-new pointer. Ignoring the result leaves
// a stale pointer. Copy/union helpers that always allocate a new object
// (list_copy, list_concat_copy, bms_copy, bms_union, …) are not included.
bool isRecyclingName(StringRef Name) {
  return llvm::StringSwitch<bool>(Name)
      .Cases("lappend", "lappend_int", "lappend_oid", "lappend_xid", true)
      .Cases("list_insert_nth", "list_insert_nth_int", "list_insert_nth_oid",
             true)
      .Cases("lcons", "lcons_int", "lcons_oid", true)
      .Cases("list_concat", "list_truncate", true)
      .Cases("list_delete", "list_delete_ptr", "list_delete_int",
             "list_delete_oid", "list_delete_first", "list_delete_last",
             "list_delete_first_n", "list_delete_nth_cell", "list_delete_cell",
             true)
      .Cases("list_append_unique", "list_append_unique_ptr",
             "list_append_unique_int", "list_append_unique_oid", true)
      .Cases("list_concat_unique", "list_concat_unique_ptr",
             "list_concat_unique_int", "list_concat_unique_oid", true)
      .Cases("bms_add_member", "bms_del_member", "bms_add_members",
             "bms_replace_members", "bms_add_range", "bms_int_members",
             "bms_del_members", "bms_join", true)
      .Default(false);
}

// True when E's value is discarded the way -Wunused-result / pg_nodiscard
// would complain: expression statement, comma LHS, if/for/while body, …
// An explicit (void) cast is treated as a deliberate ignore.
bool isDiscardedExpr(const Expr *E, ASTContext &Ctx) {
  const Stmt *Cur = E;
  for (unsigned Depth = 0; Depth < 32; ++Depth) {
    const DynTypedNodeList Parents = Ctx.getParents(*Cur);
    if (Parents.empty())
      return true;

    // Initializer, argument in a declarator, etc.
    if (Parents[0].get<Decl>())
      return false;

    const Stmt *PS = Parents[0].get<Stmt>();
    if (!PS)
      return false;

    if (isa<ParenExpr>(PS) || isa<ImplicitCastExpr>(PS) || isa<FullExpr>(PS) ||
        isa<ConstantExpr>(PS)) {
      Cur = PS;
      continue;
    }

    if (const auto *CE = dyn_cast<CastExpr>(PS)) {
      if (CE->getCastKind() == CK_ToVoid)
        return false;
      Cur = PS;
      continue;
    }

    if (const auto *BO = dyn_cast<BinaryOperator>(PS)) {
      if (BO->getOpcode() == BO_Comma) {
        if (BO->getLHS() == Cur)
          return true;
        Cur = PS;
        continue;
      }
      return false;
    }

    if (const auto *CO = dyn_cast<ConditionalOperator>(PS)) {
      if (CO->getCond() == Cur)
        return false;
      Cur = PS;
      continue;
    }

    if (isa<BinaryConditionalOperator>(PS)) {
      Cur = PS;
      continue;
    }

    if (const auto *CS = dyn_cast<CompoundStmt>(PS)) {
      const DynTypedNodeList GP = Ctx.getParents(*CS);
      if (!GP.empty()) {
        if (GP[0].get<StmtExpr>() && CS->body_back() == Cur)
          return false;
      }
      return true;
    }

    if (isa<LabelStmt>(PS) || isa<DefaultStmt>(PS) || isa<AttributedStmt>(PS))
      return true;

    if (const auto *Case = dyn_cast<CaseStmt>(PS))
      return Case->getSubStmt() == Cur;

    if (const auto *If = dyn_cast<IfStmt>(PS))
      return If->getThen() == Cur || If->getElse() == Cur;

    if (const auto *W = dyn_cast<WhileStmt>(PS))
      return W->getBody() == Cur;

    if (const auto *D = dyn_cast<DoStmt>(PS))
      return D->getBody() == Cur;

    if (const auto *F = dyn_cast<ForStmt>(PS))
      return F->getBody() == Cur || F->getInc() == Cur || F->getInit() == Cur;

    return false;
  }
  return false;
}

} // namespace

void DiscardedListOrBmsResultCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(callExpr(callee(functionDecl())).bind("call"), this);
}

void DiscardedListOrBmsResultCheck::check(
    const MatchFinder::MatchResult &Result) {
  const auto *CE = Result.Nodes.getNodeAs<CallExpr>("call");
  if (!CE)
    return;
  const FunctionDecl *FD = CE->getDirectCallee();
  if (!FD || !isRecyclingName(FD->getName()))
    return;
  if (!isDiscardedExpr(CE, *Result.Context))
    return;

  diag(CE->getBeginLoc(),
       "result of '%0' discarded; the pointer may have been "
       "reallocated, so assign it back (e.g. list = lappend(list, x))")
      << FD->getName();
}

} // namespace postgres
} // namespace tidy
} // namespace clang

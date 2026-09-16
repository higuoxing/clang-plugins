#include "MissingVolatileInPgTryCheck.h"

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/DiagnosticIDs.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallBitVector.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang::ast_matchers;

namespace clang {
namespace tidy {
namespace postgres {
namespace {

bool isPgTryInternalVar(const VarDecl *VD) {
  const StringRef Name = VD->getName();
  return Name.starts_with("_save_exception_stack") ||
         Name.starts_with("_save_context_stack") ||
         Name.starts_with("_local_sigjmp_buf") ||
         Name.starts_with("_do_rethrow");
}

// Automatic, non-volatile locals/parameters that POSIX says may be
// indeterminate after longjmp. Statics, volatiles, and PG_TRY macro
// temporaries are excluded: they are not clobbered, already marked, or
// written by the TRY/CATCH expansion itself.
bool isInterestingVar(const VarDecl *VD) {
  if (!VD || !VD->isLocalVarDeclOrParm() || !VD->hasLocalStorage() ||
      VD->isStaticLocal())
    return false;
  if (VD->getType().isVolatileQualified())
    return false;
  if (isPgTryInternalVar(VD))
    return false;
  return true;
}

const BinaryOperator *asAssignment(const Stmt *S) {
  const auto *E = dyn_cast<Expr>(S);
  if (!E)
    return nullptr;
  const auto *BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts());
  if (!BO || !BO->isAssignmentOp())
    return nullptr;
  return BO;
}

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

const Stmt *nextSibling(const Stmt *S, ASTContext &Ctx) {
  const auto &Parents = Ctx.getParents(*S);
  if (Parents.empty())
    return nullptr;
  const auto *CS = Parents[0].get<CompoundStmt>();
  if (!CS)
    return nullptr;
  const Stmt *Prev = nullptr;
  for (const Stmt *Child : CS->body()) {
    if (Prev == S)
      return Child;
    Prev = Child;
  }
  return nullptr;
}

const Stmt *recoveryBlock(const IfStmt *If, ASTContext &Ctx, bool &IsFinally) {
  IsFinally = false;
  const Stmt *Else = If->getElse();
  if (!Else)
    return nullptr;
  if (isDoRethrowAssign(Else)) {
    IsFinally = true;
    return nextSibling(If, Ctx);
  }
  return Else;
}

const FunctionDecl *enclosingFunction(const Stmt *S, ASTContext &Ctx) {
  DynTypedNode Node = DynTypedNode::create(*S);
  for (;;) {
    const auto &Parents = Ctx.getParents(Node);
    if (Parents.empty())
      return nullptr;
    if (const auto *FD = Parents[0].get<FunctionDecl>())
      return FD;
    Node = Parents[0];
  }
}

enum class UseKind { Ignore, Read, SimpleWrite, ReadWrite };

UseKind classifyUse(const DeclRefExpr *DRE, ASTContext &Ctx) {
  const Stmt *Cur = DRE;
  for (;;) {
    const auto &Parents = Ctx.getParents(*Cur);
    if (Parents.empty())
      return UseKind::Read;

    if (Parents[0].get<ParenExpr>() || Parents[0].get<ImplicitCastExpr>() ||
        Parents[0].get<CStyleCastExpr>()) {
      if (const auto *P = Parents[0].get<Stmt>()) {
        Cur = P;
        continue;
      }
    }

    if (const auto *BO = Parents[0].get<BinaryOperator>()) {
      if (BO->isAssignmentOp() &&
          BO->getLHS()->IgnoreParenCasts() == DRE)
        return BO->isCompoundAssignmentOp() ? UseKind::ReadWrite
                                            : UseKind::SimpleWrite;
    }
    if (const auto *UO = Parents[0].get<UnaryOperator>()) {
      if (UO->getOpcode() == UO_AddrOf &&
          UO->getSubExpr()->IgnoreParenCasts() == DRE)
        return UseKind::Ignore;
      if (UO->isIncrementDecrementOp() &&
          UO->getSubExpr()->IgnoreParenCasts() == DRE)
        return UseKind::ReadWrite;
    }
    return UseKind::Read;
  }
}

struct VarUse {
  SourceLocation Write;
  SourceLocation Read;
};

class WriteCollector : public RecursiveASTVisitor<WriteCollector> {
  ASTContext &Ctx;
  llvm::DenseMap<const VarDecl *, VarUse> &Uses;

public:
  WriteCollector(ASTContext &Ctx, llvm::DenseMap<const VarDecl *, VarUse> &Uses)
      : Ctx(Ctx), Uses(Uses) {}

  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
    if (!isInterestingVar(VD))
      return true;
    UseKind K = classifyUse(DRE, Ctx);
    if (K == UseKind::SimpleWrite || K == UseKind::ReadWrite) {
      VarUse &U = Uses[VD];
      if (U.Write.isInvalid())
        U.Write = DRE->getLocation();
    }
    return true;
  }
};

class CatchUseVisitor : public RecursiveASTVisitor<CatchUseVisitor> {
  ASTContext &Ctx;
  const llvm::DenseMap<const VarDecl *, unsigned> &Index;
  llvm::SmallBitVector &Defined;
  llvm::DenseMap<const VarDecl *, VarUse> &Uses;

  void apply(const VarDecl *VD, UseKind K, SourceLocation Loc) {
    if (!VD)
      return;
    auto It = Index.find(VD);
    if (It == Index.end())
      return;
    const unsigned I = It->second;
    switch (K) {
    case UseKind::Ignore:
      break;
    case UseKind::Read:
      if (!Defined[I] && Uses[VD].Read.isInvalid())
        Uses[VD].Read = Loc;
      break;
    case UseKind::SimpleWrite:
      Defined[I] = true;
      break;
    case UseKind::ReadWrite:
      if (!Defined[I] && Uses[VD].Read.isInvalid())
        Uses[VD].Read = Loc;
      Defined[I] = true;
      break;
    }
  }

public:
  CatchUseVisitor(ASTContext &Ctx,
                  const llvm::DenseMap<const VarDecl *, unsigned> &Index,
                  llvm::SmallBitVector &Defined,
                  llvm::DenseMap<const VarDecl *, VarUse> &Uses)
      : Ctx(Ctx), Index(Index), Defined(Defined), Uses(Uses) {}

  // Substatement CFGs often keep `x = x + 1` as one node. Walk the RHS first
  // so the clobber load is visible before the assignment kills it.
  bool TraverseBinaryOperator(BinaryOperator *BO) {
    if (!BO->isAssignmentOp())
      return RecursiveASTVisitor::TraverseBinaryOperator(BO);
    TraverseStmt(BO->getRHS());
    if (const auto *DRE =
            dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenCasts()))
      apply(dyn_cast<VarDecl>(DRE->getDecl()),
            BO->isCompoundAssignmentOp() ? UseKind::ReadWrite
                                         : UseKind::SimpleWrite,
            DRE->getLocation());
    else
      TraverseStmt(BO->getLHS());
    return true;
  }

  bool VisitDeclRefExpr(DeclRefExpr *DRE) {
    apply(dyn_cast<VarDecl>(DRE->getDecl()), classifyUse(DRE, Ctx),
          DRE->getLocation());
    return true;
  }
};

void transferStmt(const Stmt *S, ASTContext &Ctx,
                  const llvm::DenseMap<const VarDecl *, unsigned> &Index,
                  llvm::SmallBitVector &Defined,
                  llvm::DenseMap<const VarDecl *, VarUse> &Uses) {
  CatchUseVisitor V(Ctx, Index, Defined, Uses);
  V.TraverseStmt(const_cast<Stmt *>(S));
}

void collectCatchReads(const Stmt *Recovery, const FunctionDecl *FD,
                       ASTContext &Ctx,
                       llvm::DenseMap<const VarDecl *, VarUse> &Uses) {
  llvm::SmallVector<const VarDecl *, 8> Vars;
  llvm::DenseMap<const VarDecl *, unsigned> Index;
  for (const auto &Entry : Uses) {
    if (Entry.second.Write.isInvalid())
      continue;
    Index[Entry.first] = Vars.size();
    Vars.push_back(Entry.first);
  }
  if (Vars.empty())
    return;

  CFG::BuildOptions BO;
  std::unique_ptr<CFG> Cfg =
      CFG::buildCFG(FD, const_cast<Stmt *>(Recovery), &Ctx, BO);
  if (!Cfg) {
    llvm::SmallBitVector Defined(Vars.size(), false);
    transferStmt(Recovery, Ctx, Index, Defined, Uses);
    return;
  }

  const unsigned N = Cfg->getNumBlockIDs();
  const unsigned NV = Vars.size();
  std::vector<llvm::SmallBitVector> In(N, llvm::SmallBitVector(NV, true));
  In[Cfg->getEntry().getBlockID()] = llvm::SmallBitVector(NV, false);

  llvm::SmallVector<const CFGBlock *, 16> Work;
  llvm::SmallBitVector Enqueued(N, false);
  auto enqueue = [&](const CFGBlock *B) {
    if (!B)
      return;
    const unsigned ID = B->getBlockID();
    if (Enqueued[ID])
      return;
    Enqueued[ID] = true;
    Work.push_back(B);
  };
  enqueue(&Cfg->getEntry());

  unsigned Steps = 0;
  while (!Work.empty() && Steps++ < 100000) {
    const CFGBlock *B = Work.pop_back_val();
    Enqueued[B->getBlockID()] = false;
    llvm::SmallBitVector Out = In[B->getBlockID()];
    for (const CFGElement &El : *B) {
      if (auto CS = El.getAs<CFGStmt>())
        transferStmt(CS->getStmt(), Ctx, Index, Out, Uses);
    }
    for (const CFGBlock *Succ : B->succs()) {
      if (!Succ)
        continue;
      const unsigned SID = Succ->getBlockID();
      llvm::SmallBitVector Joined = In[SID];
      Joined &= Out;
      if (Joined != In[SID]) {
        In[SID] = std::move(Joined);
        enqueue(Succ);
      }
    }
  }
}

} // namespace

void MissingVolatileInPgTryCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      ifStmt(hasCondition(binaryOperator(
                 hasOperatorName("=="),
                 hasOperands(callExpr(callee(functionDecl(hasName("__sigsetjmp")))),
                             integerLiteral(equals(0))))))
          .bind("pg_try"),
      this);
}

void MissingVolatileInPgTryCheck::check(
    const MatchFinder::MatchResult &Result) {
  const auto *If = Result.Nodes.getNodeAs<IfStmt>("pg_try");
  if (!If || !If->getThen())
    return;

  ASTContext &Ctx = *Result.Context;
  bool IsFinally = false;
  const Stmt *Recovery = recoveryBlock(If, Ctx, IsFinally);
  if (!Recovery)
    return;

  llvm::DenseMap<const VarDecl *, VarUse> Uses;
  WriteCollector WC(Ctx, Uses);
  WC.TraverseStmt(const_cast<Stmt *>(If->getThen()));

  collectCatchReads(Recovery, enclosingFunction(If, Ctx), Ctx, Uses);

  const char *RecoveryName = IsFinally ? "PG_FINALLY" : "PG_CATCH";
  for (const auto &Entry : Uses) {
    const VarDecl *VD = Entry.first;
    const VarUse &U = Entry.second;
    if (U.Write.isInvalid() || U.Read.isInvalid())
      continue;

    diag(U.Read,
         "local variable %0 is modified in PG_TRY and read in %1 without "
         "being declared volatile; its value after longjmp is indeterminate")
        << VD << RecoveryName;
    diag(U.Write, "modified here", DiagnosticIDs::Note);
    if (VD->getLocation().isValid())
      diag(VD->getLocation(), "declare this variable volatile",
           DiagnosticIDs::Note);
  }
}

} // namespace postgres
} // namespace tidy
} // namespace clang

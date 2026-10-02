// services/BranchScope.js
// Who may see what. Alerts, incident reports and member records belong to the
// NGO branch of the member they concern.
//
//   * admins and coordinators with no branch  -> see everything
//   * coordinators with a branch              -> see their branch, plus anything
//                                                not assigned to a branch yet
//
// "Not assigned" items stay visible to every coordinator on purpose: an SOS must
// never go unseen because a member hasn't been placed in a branch.
function scopeFor(user) {
  if (!user || user.role === 'admin' || !user.ngoBranch) return { all: true, branchId: null };
  return { all: false, branchId: user.ngoBranch };
}

function canAccess(user, itemBranchId) {
  const scope = scopeFor(user);
  return scope.all || !itemBranchId || String(itemBranchId) === String(scope.branchId);
}

module.exports = { scopeFor, canAccess };

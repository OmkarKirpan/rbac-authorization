const { newEnforcer } = require("casbin");
const express = require("express");
const bodyParser = require("body-parser");
var authz = require("casbin-express-authz");
const app = express();

app.use(bodyParser.json());

app.use((req, res, next) => {
  const username = req.get("Authorization") || "anonymous";
  req.user = {
    username,
  };
  next();
});

//get grouping policy
app.get("/roles", async (req, res) => {
  const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
  var gPolicy = await e.getGroupingPolicy();
  var policy = await e.getPolicy();
  var allRoles = await e.getAllRoles();
  res.status(200).json({
    status: "OK",
    allRoles: allRoles,
    policy: policy,
    groupingPolicy: gPolicy,
  });
});

//get roles for user
app.get("/roles/getrole", async (req, res) => {
  const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
  var result = await e.getRolesForUser(req.user.username);
  var result0 = await e.getPermissionsForUser(req.user.username);
  var result1 = await e.getImplicitRolesForUser(req.user.username);
  var result2 = await e.getImplicitPermissionsForUser(req.user.username);

  res.status(200).json({
    status: "OK",
    user: req.user.username,
    roles: result,
    implicitRoles: result1,
    permissions: result0,
    implicitPermissions: result2,
  });
});

//get user for role
app.get("/roles/getusers", async (req, res) => {
  const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
  var result = await e.getUsersForRole(req.query.role);

  res.status(200).json({
    status: "OK",
    users: result,
    role: req.query.role,
  });
});

//get grouping policy
app.get("/roles/g", async (req, res) => {
  const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
  var result = await e.getGroupingPolicy();
  res.status(200).json({
    status: "OK",
    policy: result,
  });
});

//add grouping policy
app.post("/roles/g", async (req, res) => {
  if (req.body.role !== undefined) {
    const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
    var result = await e.addGroupingPolicy(req.user.username, req.body.role);
    e.savePolicy();
  }
  res.status(200).json({
    status: "OK",
    policyAdded: result,
  });
});

//remove grouping policy
app.delete("/roles/g", async (req, res) => {
  if (req.body.role !== undefined) {
    const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
    var result = await e.removeGroupingPolicy(req.user.username, req.body.role);
    e.savePolicy();
  }
  res.status(200).json({
    status: "OK",
    policyRemoved: result,
  });
});

//get policy
app.get("/roles/p", async (req, res) => {
  const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
  var result = await e.getPolicy();
  res.status(200).json({
    status: "OK",
    policy: result,
  });
});

//add policy
app.post("/roles/p", async (req, res) => {
  if (
    req.body.sub !== undefined &&
    req.body.obj !== undefined &&
    req.body.act !== undefined
  ) {
    const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
    var result = await e.addPolicy(req.body.sub, req.body.obj, req.body.act);
    e.savePolicy();
  }
  res.status(200).json({
    status: "OK",
    policyAdded: result,
  });
});

//remove policy
app.delete("/roles/p", async (req, res) => {
  if (
    req.body.sub !== undefined &&
    req.body.obj !== undefined &&
    req.body.act !== undefined
  ) {
    const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
    var result = await e.removePolicy(req.body.sub, req.body.obj, req.body.act);
    e.savePolicy();
  }
  res.status(200).json({
    status: "OK",
    policyRemoved: result,
  });
});

//add role for user
app.post("/roles/addrole", async (req, res) => {
  if (req.body.role !== undefined) {
    const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
    var result = await e.addRoleForUser(req.user.username, req.body.role);
    e.savePolicy();
  }
  res.status(200).json({
    status: "OK",
    roleAdded: result,
  });
});

//delete a role for user
app.post("/roles/removerole", async (req, res) => {
  if (req.body.role !== undefined) {
    const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
    var result = await e.deleteRoleForUser(req.user.username, req.body.role);
    e.savePolicy();
  }
  res.status(200).json({
    status: "OK",
    roleAdded: result,
  });
});

//delete all roles for user
app.post("/roles/removeallrole", async (req, res) => {
  const e = await newEnforcer("authz_model.conf", "authz_policy.csv");
  var result = await e.deleteRolesForUser(req.user.username);
  e.savePolicy();

  res.status(200).json({
    status: "OK",
    roleAdded: result,
  });
});

app.use(
  authz(async () => {
    // load the casbin model and policy from files, database is also supported.
    const enforcer = await newEnforcer("authz_model.conf", "authz_policy.csv");
    return enforcer;
  })
);

app.use(async (req, res, next) => {
  const enforcer = await newEnforcer("authz_model.conf", "authz_policy.csv");
  console.log(req.user.username);
  const roles = await enforcer.getImplicitPermissionsForUser(req.user.username);
  // const roles = await enforcer.addPermissionForUser("omkar", [
  //   "/datasetOK1/ *",
  //   "GET",
  // ]);
  // enforcer.savePolicy();
  res.status(200).json({
    status: "OK",
    roles: await roles,
  });
});

app.listen(3000);

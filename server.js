const { newEnforcer } = require("casbin");
const express = require("express");
const authz = require("casbin-express-authz");

const app = express();

app.use((req, res, next) => {
  const username = req.get("Authorization") || "anonymous";
  req.user = { username };
  next();
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
  res.status(200).json({ status: "OK", roles: await roles });
});

app.listen(3000);

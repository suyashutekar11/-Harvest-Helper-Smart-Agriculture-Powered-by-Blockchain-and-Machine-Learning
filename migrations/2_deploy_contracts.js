const CropApplication = artifacts.require("CropApplication");

module.exports = function (deployer, network, accounts) {
  const adminAddress = accounts[0];  // Use the first account as admin
  deployer.deploy(CropApplication, adminAddress);
};

const { exec } = require("child_process");

module.exports = function greet(name) {
  return "Hello, " + name;
};

module.exports.run = function(cmd) {
  return new Promise((resolve, reject) => {
    child_process.exec(cmd, (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
};

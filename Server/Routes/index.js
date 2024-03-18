const express = require("express");
const router = express();

// http://localhost:4000/ 으로 접속 시 응답메시지 출력
router.post("/", (req, res) => {
  res.send({ test: "this is test!!" });
});

router.post("/login", (req, res) => {
  res.send({ test: "this is test!!" });
});

router.post("/edu_calendar", (req, res) => {
  res.send({ test: "this is test!!" });
});

module.exports = router;

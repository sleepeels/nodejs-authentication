const router = require("express").Router();
const verify = require("./verifyToken");

router.get("/", verify, (req, res) => {
  //   res.json({ posts: { title: "first one", description: "random text" } });
  res.send(req.user);
});

module.exports = router;

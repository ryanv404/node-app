const chai = require("chai");
const chaiHttp = require("chai-http");
const server = require("../app");
const should = chai.should();
const Review = require("../models/Review");

chai.use(chaiHttp);

describe("Reviews", () => {
  // TEST INDEX
  it("should index ALL reviews on / GET", (done) => {
    chai
      .request(server)
      .get("/reviews")
      .end((err, res) => {
        res.should.have.status(200);
        res.should.be.html;
        done();
      });
  });

  // TEST NEW
  // TEST CREATE
  // TEST SHOW
  // TEST EDIT
  // TEST UPDATE
  // TEST DELETE
});
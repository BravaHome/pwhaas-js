"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const chai = require("chai");
const index_1 = require("../src/index");
describe("can run the examples", () => {
    it("can set options", function () {
        index_1.pwhaas.setOptions({
            apiKey: "[Your API Key Here]",
            maxtime: 250,
            serviceRootUri: "https://api.pwhaas.com",
            request: {
                timeout: 5000
            }
        });
        //back to default options so we don't screw with other tests
        index_1.pwhaas.setOptions({});
    });
    it("can do the basic example", function () {
        return __awaiter(this, void 0, void 0, function* () {
            this.timeout(0);
            const plain = "password";
            // Init the service once before using it.
            // This will find some secure hash options to use for local hashing in case pwhaas is unreachable.
            yield index_1.pwhaas.init();
            // Hashing happens in an asynchronous event using libuv so your system can
            // still process other IO items in the Node.JS queue, such as web requests.
            const hashResponse = yield index_1.pwhaas.hash(plain);
            // This hash is what you should store in your database. Treat it as an opaque string.
            // The response also contains information on how long the hashing took, the
            // Argon2 options that were used, and whether or not we had to fall back to hashing locally.
            console.log(hashResponse.hash);
            // Verifying the hash against your user's password is simple.
            const verifyResponse = yield index_1.pwhaas.verify(hashResponse.hash, plain);
            console.log(verifyResponse.match);
            chai.assert.isTrue(verifyResponse.match, "password doesn't match hash");
        });
    });
    it("can do a non-default timing", function () {
        return __awaiter(this, void 0, void 0, function* () {
            this.timeout(0);
            const hashResponse = yield index_1.pwhaas.hash("password", 1000);
            chai.assert.isNotNull(hashResponse.hash, "didn't actually hash");
            chai.assert.isNotTrue(hashResponse.local, "hash was done locally");
        });
    });
    it("can create an instance of Pwhaas", function () {
        return __awaiter(this, void 0, void 0, function* () {
            this.timeout(0);
            const pwhaas = new index_1.Pwhaas({ apiKey: "[Your API Key Here]" });
            yield pwhaas.init();
            const hashResponse = yield pwhaas.hash("password", 100);
            chai.assert.isNotNull(hashResponse.hash, "didn't actually hash");
            chai.assert.isNotTrue(hashResponse.local, "hash was done locally");
        });
    });
});

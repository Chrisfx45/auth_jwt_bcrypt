import express,{ Router } from "express";
import { payment } from "../controllers/transaction.controller";

const TRouter : Router = express.Router()

TRouter.post("/payment", payment)

export default TRouter
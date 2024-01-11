import express, { Router } from "express"
import * as productControl from "./../controllers/product.controller"
import { verifyToken, adminGuard, adminUser} from "../middlewares/auth.middleware"
const PRouter : Router = express.Router()


PRouter.get("/product-secret",verifyToken,adminGuard, productControl.getSecretP)
PRouter.get("/product-user",verifyToken, adminUser, productControl.getUserP)
PRouter.get("/product", productControl.getP)


export default PRouter
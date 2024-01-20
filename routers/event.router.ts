import express, { Router } from "express"
import * as AuthControl from "./../controllers/auth.controller"
import * as EventControl  from "./../controllers/event.controller"

const eventRouter : Router = express.Router()

eventRouter.post("/create", EventControl.createEvent)



export default eventRouter
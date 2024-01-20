import { Express, Request, Response, NextFunction} from "express";
import { verify } from "jsonwebtoken";
type User ={
    email : String;
    name : String;
    password : String;
    role? : String;
};

export const verifyToken =async( req : Request, res : Response, next : NextFunction)=>{
    try{
        const token = req.header("Authorization")?.replace("Bearer ", "");
        if(!token){
            return res.status(401).send({
                msg :"Unauthorized?",
                token : token});
        }
        const verifiedUser = verify(token,"your-key");
        if(!verifiedUser){
            return res.status(401).send("Unauthorized");
        }
        req.user = verifiedUser as User;
        next();
        
    }catch(err){
        return res.status(500).send({
            message :JSON.stringify(err),
            data : []
        })

    }
}
export const adminGuard = async( req : Request, res : Response, next : NextFunction)=>{
    try{
        if(req.user?.role != "admin"){
            return res.status(401).send({
                msg :"Unauthorized",
                role : req.user?.role
        });

        }
        next();

    }
    catch(err){
        return res.status(500).send({
            message :JSON.stringify(err),
            data : []
        })
    }
}

export const adminUser = async( req : Request, res : Response, next : NextFunction)=>{
    try{
        if(req.user?.role ! == "" ){

            return res.status(401).send({
                msg :"Unauthorized",
                data : req.user?.role
            });

        }
        next();

    }
    catch(err){
        return res.status(500).send({
            message :JSON.stringify(err),
            data : []
        })
    }
}


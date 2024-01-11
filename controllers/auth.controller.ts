import express, {Response, Request} from "express";
import {genSalt, hash, compare} from "bcrypt" 
import { PrismaClient } from "@prisma/client";
import { JwtPayload, sign } from "jsonwebtoken";

type User ={
    email : String;
    name : String;
    password : String;
    role : String;
};

const prisma = new PrismaClient();



export async function register (req: Request, res : Response){
    try{
        const {name, email , password} = req.body

        const finduser = await prisma.user.findFirst({
            where :{
                email: email
            },
        })
        if (finduser){
            return res.status(400).send({
                message : "Email has already registerd",
                data : {}
            })
        }
        

        const salt = await genSalt(10)
        const hashedPass = await hash (password, salt)

        const createUser = await prisma.user.create(
            {
                data :{
                    name : name,
                    email : email,
                    password : hashedPass,
                    created_at : new Date()
                }
            }
        )
        return res.status(200).send({
            message : "OK",
            data : createUser
        })

    }catch(err){
        return res.status(500).send({
            message :JSON.stringify(err),
            data : []
        })

    }

}

export async function login( req : Request, res :Response){

    try{
        const {email , password} = req.body

        const finduser = await prisma.user.findFirst({
            where :{
                email: email
            },
        })
        if (!finduser){
            return res.status(404).send({
                message : "Invalid email or password",
                data : {}
            })
            
        }
        const isValidUser = await compare(password, finduser.password)

        if (!isValidUser){
            return res.status(404).send({
                message : "Invalid email or password",
                data : {}
            })
        }
        const jwtpayload = {email : email, role : finduser.role};
        const token = sign(jwtpayload, "your-key", {expiresIn : "1h"})

        
        return res.status(200).send({
            message : "OK",
            data : finduser, 
            token :token
        })

    }catch(err){
        return res.status(500).send({
            message :JSON.stringify(err),
            data : []
        })

    }

}
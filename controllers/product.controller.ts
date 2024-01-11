import express, {Response, Request} from "express";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient()


export async function getSecretP( req : Request, res :Response) {
    return res.status(200).send({
        message : "OK",
        data : "Secret Product"
    })
}
export async function getUserP( req : Request, res :Response) {
    return res.status(200).send({
        message : "OK",
        data : "User Product"
    })
}

export async function getP( req : Request, res :Response) {
    return res.status(200).send({
        message : "OK",
        data : "Product"
    })
}
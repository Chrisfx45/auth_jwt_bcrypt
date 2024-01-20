import express, {Request, Response}from "express"
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient()


export async function createEvent( req : Request, res : Response){
    try{
        const {userID, name, availableseats, price} = req.body
        const finduser = await prisma.user.findFirst({
            where : {id : userID}
        })

        if (!finduser ){
            console.log("user found")
            return res.status(400).send({
                message : "User does not exist",
                data : {}
                
            })
        }
        console.log(userID)

        const createEvents = await prisma.event.create({
            data :{
                name : name,
                availableseats :  availableseats,
                price : price,
                organizer: {
                    connect: { id: userID },
                  }

            }
        })
        console.log(createEvents.id)
        const updateUser = await prisma.user.update({
            where :{id : userID},
            data :{
                eventcreate :{
                    connect :[{ id : createEvents.id}]
                }
            },
            include :{
                eventcreate : true,
                transaction : true
            }
        })
        return res.status(200).send({
            message : "OK",
            data : createEvents,
            data1 : updateUser

        })   

    }
    catch(error){
        console.log(error)
        return res.status(500).send({
            message :JSON.stringify(error),
            data :req.body
        })

    }

}


export async function getEvent(){}

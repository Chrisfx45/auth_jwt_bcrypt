import { PrismaClient } from "@prisma/client"
import express, {Response, Request}from "express"


const prisma = new PrismaClient

export async function payment(req : Request, res : Response){

    try {
        const {userID, eventID, amount, points} = req.body
        const finduser = await prisma.user.findUnique({
            where:{
                id : userID
            }

        })
        if (!finduser){
            console.log("user not found")
            return res.status(400).send({
                message : "User does not exist",
                data : {}
                
            })
        }
        const findevent = await prisma.event.findUnique({
            where :{
                id : eventID
            }
        })
        if (!findevent){
            console.log("event not found")
            return res .status(400).send({
                message : "Event does not exist",
                data : {}
                
            })
        }
        const usrpoints = finduser.points
        const wallet = finduser.wallet

        const seats = findevent.availableseats
        const Bseats = findevent.bookedseats
        const price = findevent.price

        const totalP = price*amount
        const payed = totalP - points
        
        const createTransactions = await prisma.transaction.create({
            data:{
                amount :amount,
                points : points,
                money : payed,
                total : totalP,
                buyer :{
                    connect :{id : userID}
                },
                eventbought :{
                    connect :{id :eventID}
                }

            }
        })
        const updateUser = await prisma.user.update({
            where :{id : userID},
            data :{
                points : usrpoints -points,
                wallet : wallet -payed,
                transaction :{
                    connect :[{id : createTransactions.id}]
                }
            },
            include :{
                eventcreate : true,
                transaction : true
            }
        })
        const updateEvents = await prisma.event.update({
            where :{id : eventID},
            data :{
                availableseats : seats-amount,
                bookedseats : Bseats +amount,
                transactions :{
                    connect :[{id : createTransactions.id}]
                }
            },
            include :{
                transactions   : true
            }
        })
        return res.status(200).send({
            message : "OK",
            data : createTransactions,
            data1 : updateUser,
            data2 : updateEvents

        })   
        

    }catch(error){
        return res.status(500).send({
            message :JSON.stringify(error),
            data :req.body
        })
    }

}
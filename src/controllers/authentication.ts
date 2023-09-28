import { createUser, getUserByEmail } from "../db/users";
import express from "express";
import { random } from "../helpers";
import { authentication } from '../helpers/index';


export const login = async(req: express.Request, res: express.Response) =>{
    try {
        const  {email, password} = req.body

        if(!email || !password){
            return res.status(400).send("Fill the Complete details")
        }

        const user = await getUserByEmail(email).select('+authentication.salt +authentication.password')

        if(!user) {
            return res.status(400).send("User Not there")
        }

        const expectedHash = authentication(user.authentication.salt, password)

        if(user.authentication.password !== expectedHash){
            return res.status(400).send("InCorrect Details")
        }

        const salt = random()
        user.authentication.sessionToken = authentication(salt, user._id.toString())

        await user.save()

        res.cookie('auth',user.authentication.sessionToken,{ domain :'localhost', path:'/'})

        return res.status(200).json(user).end()

    } catch(error){
        console.log(error)
        return res.status(400).json(error)
    }
}




export const register = async(req: express.Request, res: express.Response) => {
    try{
        const {email, password, username} = req.body;

        if(!email || !password || !username){
            return res.sendStatus(400)
        }

        const existingUser = await getUserByEmail(email)

        if(existingUser){
            return res.status(400).send("User already there")
        }

        const salt = random()
        const hash_password = authentication(salt, password)
        const user = await createUser({
            email,
            username,
            authentication:{
                salt,
                password: hash_password
            }
        })

        return res.status(200).json(user).end()

    }catch(error){
        console.log(error)
        return res.status(400).json(error)
    }
}






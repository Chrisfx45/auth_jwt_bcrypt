type User ={
    email : String;
    name : String;
    password : String;
    role? : String;
};
declare namespace Express{
    export interface Request{
        user?: User;
    }
}
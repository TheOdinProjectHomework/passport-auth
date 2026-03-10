import mongoose from "mongoose";

export const connectDB = async () => {
    try {
        const con = await mongoose.connect(process.env.MONGO_URI);
        console.log(`Mongo DB Connected: ${con.connection.host}`);
    } catch (error) {
        console.log("Error connecting to db: ", error.message);
        process.exit(1);
    }
}
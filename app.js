import path from "path"
import { connectDB } from "./db/connectDB.js"
import { Pool } from "pg"
import express from "express"
import session from "express-session"
import passport from "passport"
import dotenv from "dotenv"
import { Strategy as LocalStrategy } from "passport-local"
import { fileURLToPath } from "url"
import { User } from "./model/user.model.js"
import bcrypt from "bcryptjs"
import helmet from "helmet";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(helmet());
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  }),
);
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

passport.use(
    new LocalStrategy(async (username, password, done) => {
        try {
            const user = await User.findOne({ username });
            
            if(!user) return done(null, false, { message: "Incorrect username" });
            // if(user.password !== password) return done(null, false, { message: "Incorrect password" });
            const match = await bcrypt.compare(password, user.password);
            if(!match) return done(null, false, { message: "Incorrect password" });


            return done(null, user);
        } catch (error) {
            return done(error);
        }
    })
)

passport.serializeUser((user, done) => {
    done(null, user._id)
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
})

app.get("/", (req, res) => res.render("index", { user: req.user }));
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
    const { username, password } = req.body;

    try {
        const userAlreadyExists = await User.findOne({ username });

        if(userAlreadyExists) return res.status(400).json({ success: false, message: "User already exists"});

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            password: hashedPassword,
        });

        // console.log(user); 
        await user.save();

        res.redirect("/");
    } catch (error) {
        return next(error);
    }
})

app.post("/log-in", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
}));

app.get("/log-out", (req, res, next) => {
    req.logout((err) => {
        if(err) {
            return next(err);
        }
        res.redirect("/");
    })
})

const PORT = process.env.PORT || 5000;

app.listen(PORT, (error) => {
    connectDB();
    if(error) {
        throw error;
    }
    console.log("server listening on port: ", PORT);
})
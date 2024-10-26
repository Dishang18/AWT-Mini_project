const express = require('express');
const app = express();
const path = require('path');

const userModel = require('./models/user');
const postModel = require('./models/post');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

app.get("/", function(req, res) {
    res.render("index"); // Render the home page (index.ejs)
});

// GET route for register page
app.get("/register", function(req, res) {
    res.render("register"); // Render the register form (register.ejs)
});

// GET route for login page
app.get("/login", function(req, res) {
    res.render("login"); // Render the login form (login.ejs)
});

// POST route for user registration
app.post("/register", async function(req, res) {
    let { email, username, password, name, age } = req.body;

    let user = await userModel.findOne({ email });
    if (user) return res.status(500).send("User Already Registered!!!");

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, async (err, hash) => {
            let newUser = await userModel.create({
                username,
                email,
                password: hash,
                name,
                age
            });

            let token = jwt.sign({ email: email, userId: newUser._id }, "secret");
            res.cookie("token", token);
            res.redirect("/login");  // Redirect to login page after registration
        });
    });
});

// POST route for login
app.post("/login", async function(req, res) {
    let { email, password } = req.body;

    let user = await userModel.findOne({ email });
    if (!user) return res.status(500).send("Something is Wrong!!!");

    bcrypt.compare(password, user.password, function(err, result) {
        if (result) {
            let token = jwt.sign({ email: email, userId: user._id }, "secret");
            res.cookie("token", token);
            res.status(200).redirect("/profile");
        } else {
            res.redirect("/login");
        }
    });
});

// GET route for user profile (must be logged in)
app.get("/profile", isLoggedIn, async function(req, res) {
    let user = await userModel.findOne({ email: req.user.email }).populate("posts");
    res.render("profile", { user });
});

// POST route for creating new post
app.post("/post", isLoggedIn, async function(req, res) {
    let user = await userModel.findOne({ email: req.user.email });
    let { content } = req.body;
    let post = await postModel.create({
        user: user._id,
        content
    });
    user.posts.push(post._id);
    await user.save();
    res.redirect("/profile");
});

// POST route for deleting a post
app.post("/post/delete/:id", isLoggedIn, async (req, res) => {
    const postId = req.params.id;

    try {
        const post = await postModel.findById(postId);

        // Check if the logged-in user is the owner of the post
        if (post.user.toString() === req.user.userId) {
            await postModel.findByIdAndDelete(postId);
            await userModel.findByIdAndUpdate(req.user.userId, {
                $pull: { posts: postId }
            });
            res.redirect("/profile");
        } else {
            res.status(403).send("You are not authorized to delete this post.");
        }
    } catch (err) {
        res.status(500).send("Error deleting post.");
    }
});

// GET route for editing a post
app.get("/post/edit/:id", isLoggedIn, async (req, res) => {
    const postId = req.params.id;

    try {
        const post = await postModel.findById(postId);

        // Check if the logged-in user is the owner of the post
        if (post.user.toString() === req.user.userId) {
            res.render("editPost", { post });
        } else {
            res.status(403).send("You are not authorized to edit this post.");
        }
    } catch (err) {
        res.status(500).send("Error fetching post.");
    }
});

// POST route for updating a post
app.post("/post/edit/:id", isLoggedIn, async (req, res) => {
    const postId = req.params.id;
    const { content } = req.body;

    try {
        const post = await postModel.findById(postId);

        // Check if the logged-in user is the owner of the post
        if (post.user.toString() === req.user.userId) {
            post.content = content;
            await post.save();
            res.redirect("/profile");
        } else {
            res.status(403).send("You are not authorized to edit this post.");
        }
    } catch (err) {
        res.status(500).send("Error updating post.");
    }
});

// GET route for logging out
app.get("/logout", function(req, res) {
    res.cookie("token", "");
    res.redirect("/login");
});

// Middleware to check if the user is logged in
function isLoggedIn(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect("/login");
    }

    try {
        const data = jwt.verify(token, "secret");  // Verify the JWT
        req.user = { userId: data.userId, email: data.email };  // Store userId and email
        next();
    } catch (error) {
        console.error("JWT verification failed:", error);
        res.redirect("/login");
    }
}

app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});

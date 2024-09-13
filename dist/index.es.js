import $hgUW1$fs from "fs";
import $hgUW1$express, {Router as $hgUW1$Router} from "express";
import $hgUW1$cors from "cors";
import $hgUW1$morgan from "morgan";
import $hgUW1$path from "path";
import {Buffer as $hgUW1$Buffer} from "buffer";
import {PrismaClient as $hgUW1$PrismaClient} from "@prisma/client";
import $hgUW1$jsonwebtoken from "jsonwebtoken";
import {cwd as $hgUW1$cwd} from "process";
import $hgUW1$bcrypt from "bcrypt";
import {object as $hgUW1$object, string as $hgUW1$string, number as $hgUW1$number} from "yup";
import $hgUW1$nodemailer from "nodemailer";

function $parcel$export(e, n, v, s) {
  Object.defineProperty(e, n, {get: v, set: s, enumerable: true, configurable: true});
}





class $11c86dc98967509f$export$2e2bcd8739ae039 {
    constructor(client){
        this.client = client;
    }
    async findByEmail(email) {
        const user = await this.client.user.findFirst({
            where: {
                email: email
            },
            // @ts-ignore
            include: {
                role: true
            }
        });
        return user;
    }
    async findByConfirmationCode(confirmationCode) {
        const user = await this.client.user.findFirst({
            // @ts-ignore
            where: {
                confirmationCode: confirmationCode
            }
        });
        return user;
    }
    async saveConfirmationCode(id, confirmationCode) {
        const user = await this.client.user.update({
            where: {
                id: id
            },
            // @ts-ignore
            data: {
                confirmationCode: confirmationCode
            }
        });
        return user;
    }
    async updatePassword(id, password) {
        const user = await this.client.user.update({
            where: {
                id: id
            },
            data: {
                password: password
            }
        });
        return user;
    }
    async store(data) {
        const user = await this.client.user.create({
            data: data
        });
        return user;
    }
}





class $45d3915c933c04b9$export$29cd7b75162a9425 {
    static get instance() {
        if (!$45d3915c933c04b9$export$29cd7b75162a9425._instance) $45d3915c933c04b9$export$29cd7b75162a9425._instance = new $45d3915c933c04b9$export$29cd7b75162a9425();
        return $45d3915c933c04b9$export$29cd7b75162a9425._instance;
    }
    get config() {
        return this._config;
    }
    constructor(){
        this._config = this.readConfigFile();
    }
    readConfigFile() {
        let config = null;
        if ($hgUW1$cwd().includes("dist")) config = (0, $hgUW1$fs).readFileSync((0, $hgUW1$path).resolve("../config.json"));
        else config = (0, $hgUW1$fs).readFileSync((0, $hgUW1$path).resolve("config.json"));
        return JSON.parse(config.toString());
    }
}


var $be423279252da9d8$exports = {};

$parcel$export($be423279252da9d8$exports, "BadRequestError", () => $be423279252da9d8$export$6bfa95453d427b2b);
$parcel$export($be423279252da9d8$exports, "AuthenticationError", () => $be423279252da9d8$export$cf0c46b07324e9c5);
$parcel$export($be423279252da9d8$exports, "ForbiddenError", () => $be423279252da9d8$export$6d7c35f6d47c9072);
$parcel$export($be423279252da9d8$exports, "NotFoundError", () => $be423279252da9d8$export$78c95b58762d2106);
$parcel$export($be423279252da9d8$exports, "UnprocessableEntityError", () => $be423279252da9d8$export$d191fb0a9d005daf);
class $be423279252da9d8$export$6bfa95453d427b2b extends Error {
    constructor(message){
        super(message);
        this._status = 400;
    }
    get status() {
        return this._status;
    }
}
class $be423279252da9d8$export$cf0c46b07324e9c5 extends Error {
    constructor(message){
        super(message);
        this._status = 401;
    }
    get status() {
        return this._status;
    }
}
class $be423279252da9d8$export$6d7c35f6d47c9072 extends Error {
    constructor(message){
        super(message);
        this._status = 403;
    }
    get status() {
        return this._status;
    }
}
class $be423279252da9d8$export$78c95b58762d2106 extends Error {
    constructor(message){
        super(message);
        this._status = 404;
    }
    get status() {
        return this._status;
    }
}
class $be423279252da9d8$export$d191fb0a9d005daf extends Error {
    constructor(message){
        super(message);
        this._status = 422;
    }
    get status() {
        return this._status;
    }
}


function $9efd3723d3141683$export$2288787135a8f66e(response, error) {
    const errorResponse = {
        response: response,
        error: error
    };
    console.error(`${errorResponse.error.message}`);
    response.status(errorResponse.error.status || 500).json({
        success: false,
        message: errorResponse.error.message
    });
}
function $9efd3723d3141683$export$7221f9f9609a7e93(response, statusCode, data) {
    const successResponse = {
        response: response,
        statusCode: statusCode,
        data: data
    };
    successResponse.response.status(successResponse.statusCode).json({
        success: true,
        ...successResponse.data
    });
}


const $e5d72593abdc7836$var$env = (0, $45d3915c933c04b9$export$29cd7b75162a9425).instance;
const $e5d72593abdc7836$var$userRepository = new (0, $11c86dc98967509f$export$2e2bcd8739ae039)(new (0, $hgUW1$PrismaClient)());
async function $e5d72593abdc7836$export$c807668e63e7354b(request, response, next) {
    try {
        const token = request.headers.authorization?.replace("Bearer ", "");
        const decodedToken = (0, $hgUW1$jsonwebtoken).verify(token, `${$e5d72593abdc7836$var$env.config.jwtSecret}`);
        const dbUser = await $e5d72593abdc7836$var$userRepository.findByEmail(`${decodedToken.payload}`);
        if (!dbUser) throw new (0, $be423279252da9d8$export$cf0c46b07324e9c5)("Usu\xe1rio inv\xe1lido!");
        request.user = dbUser;
        next();
    } catch (error) {
        return (0, $9efd3723d3141683$export$2288787135a8f66e)(response, error);
    }
}














"use strict";
const $7f1901e1d291bb3f$var$env = (0, $45d3915c933c04b9$export$29cd7b75162a9425).instance;
const $7f1901e1d291bb3f$var$transport = (0, $hgUW1$nodemailer).createTransport({
    host: $7f1901e1d291bb3f$var$env.config.smtpHost,
    port: $7f1901e1d291bb3f$var$env.config.smtpPort,
    secure: $7f1901e1d291bb3f$var$env.config.smtpSecure,
    auth: {
        user: $7f1901e1d291bb3f$var$env.config.smtpUser,
        pass: $7f1901e1d291bb3f$var$env.config.smtpPass
    },
    tls: {
        ciphers: "SSLv3"
    }
});
async function $7f1901e1d291bb3f$export$1cea2e25b75a88f2(emailTo, subject, html) {
    try {
        const info = await $7f1901e1d291bb3f$var$transport.sendMail({
            from: $7f1901e1d291bb3f$var$env.config.mailFrom,
            to: emailTo,
            subject: subject,
            html: html
        });
        return `Mensagem enviada para: ${info.accepted}`;
    } catch (error) {
        console.error(error);
        return `Não foi possível enviar a mensagem`;
    }
}





var $d8febce1a052e59d$var$__dirname = "src/modules/auth";
const $d8febce1a052e59d$var$env = (0, $45d3915c933c04b9$export$29cd7b75162a9425).instance;
class $d8febce1a052e59d$export$2e2bcd8739ae039 {
    constructor(prismaClient){
        this.prismaClient = prismaClient;
        this.authRepository = new (0, $11c86dc98967509f$export$2e2bcd8739ae039)(prismaClient);
    }
    _generateAuthToken(email, expiresIn = "24h") {
        return (0, $hgUW1$jsonwebtoken).sign({
            payload: email
        }, $d8febce1a052e59d$var$env.config.jwtSecret, {
            expiresIn: expiresIn
        });
    }
    async login(payload) {
        const userSchema = $hgUW1$object({
            email: $hgUW1$string().email().required(),
            password: $hgUW1$string().min(8).required()
        });
        const validatedData = await userSchema.validate(payload);
        const user1 = await this.authRepository.findByEmail(validatedData.email);
        if (!user1) throw new (0, $be423279252da9d8$export$cf0c46b07324e9c5)("Usu\xe1rio inv\xe1lido!");
        // @ts-expect-error
        if (user1 && (user1.deletedAt || !user1.active)) throw new (0, $be423279252da9d8$export$6d7c35f6d47c9072)("Usu\xe1rio inv\xe1lido!");
        const isPasswordValid = await (0, $hgUW1$bcrypt).compare(validatedData.password, user1.password);
        if (!isPasswordValid) throw new (0, $be423279252da9d8$export$cf0c46b07324e9c5)("Usu\xe1rio inv\xe1lido!");
        const { password: password , ...userResponse } = user1;
        return {
            token: this._generateAuthToken(user1.email),
            user: userResponse
        };
    }
    async register(payload) {
        const userSchema = $hgUW1$object({
            name: $hgUW1$string().min(3).required(),
            email: $hgUW1$string().email().required(),
            password: $hgUW1$string().min(8).required(),
            roleId: $hgUW1$number().required()
        });
        const validatedData = await userSchema.validate(payload);
        const isRegistered = await this.authRepository.findByEmail(validatedData.email);
        if (isRegistered) throw new (0, $be423279252da9d8$export$cf0c46b07324e9c5)("Usu\xe1rio inv\xe1lido!");
        const salt = await (0, $hgUW1$bcrypt).genSalt();
        const hashPassword = await (0, $hgUW1$bcrypt).hash(validatedData.password, salt);
        const data = {
            name: validatedData.name,
            email: validatedData.email,
            password: hashPassword,
            roleId: validatedData.roleId
        };
        validatedData.password = hashPassword;
        payload.password = hashPassword;
        const { password: password , ...userResponse } = await this.authRepository.store({
            ...data,
            ...payload
        });
        return {
            user: userResponse
        };
    }
    async forgotPassword(email) {
        const userSchema = $hgUW1$object({
            email: $hgUW1$string().email().required()
        });
        const validatedData = await userSchema.validate(email);
        const user2 = await this.authRepository.findByEmail(validatedData.email);
        if (!user2) throw new (0, $be423279252da9d8$export$cf0c46b07324e9c5)("Usu\xe1rio inv\xe1lido!");
        const template = (0, $hgUW1$fs).readFileSync((0, $hgUW1$path).resolve($d8febce1a052e59d$var$__dirname, "../../templates/forgot-password.html"));
        const token = this._generateAuthToken(user2.email, "1h");
        const success = this.authRepository.saveConfirmationCode(user2.id, token);
        if (!success) throw new (0, $be423279252da9d8$export$d191fb0a9d005daf)("Erro ao processar solicita\xe7\xe3o");
        let emailBody = template.toString().replace("{{FRONT_URL}}", $d8febce1a052e59d$var$env.config.frontURL).replace("{{TOKEN}}", `${token}`).replace("{{NAME}}", `${user2.name}`).replace("{{EMAIL}}", `${validatedData.email}`);
        const message = await (0, $7f1901e1d291bb3f$export$1cea2e25b75a88f2)(user2.email, "Esqueci Minha Senha", emailBody);
        return message;
    }
    async me(requestUser) {
        const dbUser = await this.authRepository.findByEmail(requestUser.email);
        if (!dbUser) throw new (0, $be423279252da9d8$export$78c95b58762d2106)("Usu\xe1rio n\xe3o encontrado!");
        // @ts-ignore
        const { password: password , confirmationCode: confirmationCode , ...userResponse } = dbUser;
        return {
            user: userResponse
        };
    }
    async updatePassword(payload) {
        const userSchema = $hgUW1$object({
            newPassword: $hgUW1$string().min(8).required(),
            newPasswordConfirmation: $hgUW1$string().min(8).required(),
            confirmationCode: $hgUW1$string().required()
        });
        const validatedData = await userSchema.validate(payload);
        if (validatedData.newPassword !== validatedData.newPasswordConfirmation) throw new (0, $be423279252da9d8$export$6bfa95453d427b2b)("Senha inv\xe1lida!");
        const decodedToken = (0, $hgUW1$jsonwebtoken).verify(validatedData.confirmationCode, $d8febce1a052e59d$var$env.config.jwtSecret);
        const user3 = await this.authRepository.findByConfirmationCode(validatedData.confirmationCode);
        if (!decodedToken || !user3) throw new (0, $be423279252da9d8$export$6bfa95453d427b2b)("C\xf3digo inv\xe1lido!");
        await this.authRepository.saveConfirmationCode(user3.id, null);
        const salt = await (0, $hgUW1$bcrypt).genSalt();
        const hashPassword = await (0, $hgUW1$bcrypt).hash(validatedData.newPassword, salt);
        const isPassSaved = await this.authRepository.updatePassword(user3.id, hashPassword);
        if (!isPassSaved) throw new (0, $be423279252da9d8$export$d191fb0a9d005daf)("Senha Inv\xe1lida!");
        return `Senha atualizada com sucesso!`;
    }
    async resetPassword(payload) {
        const userSchema = $hgUW1$object({
            newPassword: $hgUW1$string().min(8).required(),
            email: $hgUW1$string().required()
        });
        const validatedData = await userSchema.validate(payload);
        const user4 = await this.authRepository.findByEmail(validatedData.email);
        if (!user4) throw new (0, $be423279252da9d8$export$6bfa95453d427b2b)("Usu\xe1rio inv\xe1lido!");
        const salt = await (0, $hgUW1$bcrypt).genSalt();
        const hashPassword = await (0, $hgUW1$bcrypt).hash(validatedData.newPassword, salt);
        const isPassSaved = await this.authRepository.updatePassword(user4.id, hashPassword);
        if (!isPassSaved) throw new (0, $be423279252da9d8$export$d191fb0a9d005daf)("Senha Inv\xe1lida!");
        return `Senha atualizada com sucesso!`;
    }
}


class $c08720df553c6f5f$export$2e2bcd8739ae039 {
    constructor(prismaClient){
        this.prismaClient = prismaClient;
        this.service = new (0, $d8febce1a052e59d$export$2e2bcd8739ae039)(prismaClient);
    }
    async login(request, response) {
        try {
            const loginResponse = await this.service.login(request.body);
            return (0, $9efd3723d3141683$export$7221f9f9609a7e93)(response, 200, loginResponse);
        } catch (error) {
            return (0, $9efd3723d3141683$export$2288787135a8f66e)(response, error);
        }
    }
    async register(request, response) {
        try {
            const user = await this.service.register(request.body);
            return (0, $9efd3723d3141683$export$7221f9f9609a7e93)(response, 201, user);
        } catch (error) {
            return (0, $9efd3723d3141683$export$2288787135a8f66e)(response, error);
        }
    }
    async me(request, response) {
        try {
            const user = await this.service.me(request.user);
            return (0, $9efd3723d3141683$export$7221f9f9609a7e93)(response, 200, user);
        } catch (error) {
            return (0, $9efd3723d3141683$export$2288787135a8f66e)(response, error);
        }
    }
    async forgotPassword(request, response) {
        try {
            const message = await this.service.forgotPassword(request.body);
            return (0, $9efd3723d3141683$export$7221f9f9609a7e93)(response, 200, {
                message: message
            });
        } catch (error) {
            return (0, $9efd3723d3141683$export$2288787135a8f66e)(response, error);
        }
    }
    async updatePassword(request, response) {
        try {
            const message = await this.service.updatePassword(request.body);
            return (0, $9efd3723d3141683$export$7221f9f9609a7e93)(response, 200, {
                message: message
            });
        } catch (error) {
            return (0, $9efd3723d3141683$export$2288787135a8f66e)(response, error);
        }
    }
    async resetPassword(request, response) {
        try {
            const message = await this.service.resetPassword(request.body);
            return (0, $9efd3723d3141683$export$7221f9f9609a7e93)(response, 200, {
                message: message
            });
        } catch (error) {
            return (0, $9efd3723d3141683$export$2288787135a8f66e)(response, error);
        }
    }
}


class $6dba8dd099e08117$export$2e2bcd8739ae039 {
    constructor(prismaClient){
        this.prismaClient = prismaClient;
        this.router = (0, $hgUW1$Router)();
        this.controller = new (0, $c08720df553c6f5f$export$2e2bcd8739ae039)(prismaClient);
    }
    login() {
        this.router.post("/login", (request, response)=>{
            this.controller.login(request, response);
        });
        return this;
    }
    register() {
        this.router.post("/register", (request, response)=>{
            this.controller.register(request, response);
        });
        return this;
    }
    me() {
        this.router.get("/me", (0, $e5d72593abdc7836$export$c807668e63e7354b), (request, response)=>{
            this.controller.me(request, response);
        });
        return this;
    }
    forgotPassword() {
        this.router.post("/forgot-password", (request, response)=>{
            this.controller.forgotPassword(request, response);
        });
        return this;
    }
    updatePassword() {
        this.router.patch("/update-password", (request, response)=>{
            this.controller.updatePassword(request, response);
        });
        return this;
    }
    resetPassword() {
        this.router.patch("/reset-password", (request, response)=>{
            this.controller.resetPassword(request, response);
        });
        return this;
    }
}



class $b19745b8f5f6cb44$export$2e2bcd8739ae039 {
    isPublic = true;
    constructor(moduleName){
        this.moduleName = moduleName;
        this.router = new (0, $6dba8dd099e08117$export$2e2bcd8739ae039)(new (0, $hgUW1$PrismaClient)());
        this.loadRoutes();
    }
    loadRoutes() {
        this.router.login().register().forgotPassword().updatePassword().me().resetPassword();
    }
}





class $f068a559611004a3$export$98f03c5d19621d70 {
    includeParamsRelations(query) {
        const relations = query?.split(",");
        if (!relations || relations.length == 0) return {};
        let params = {};
        relations.forEach((relation)=>{
            if (relation.includes(".")) {
                const linkedRelations = relation.split(".");
                if (linkedRelations[1].includes("*")) {
                    // ! O formato pode vir desta maneira user.city*state
                    const nestedRelations = linkedRelations[1].split("*");
                    let include = {};
                    nestedRelations.forEach((nestedRelation)=>{
                        // ! O trecho pode repetir mais de 2 vezes, então com esse foreach ele vai formatar no formato do objeto que o prisma precisa
                        // ! Por exemplo: {city: true, state: true}
                        include = {
                            ...include,
                            [nestedRelation]: true
                        };
                    });
                    params = {
                        ...params,
                        [linkedRelations[0]]: {
                            include: include
                        }
                    };
                } else params = {
                    ...params,
                    [linkedRelations[0]]: {
                        include: {
                            [linkedRelations[1]]: true
                        }
                    }
                };
            } else params = {
                ...params,
                [relation]: true
            };
        });
        return {
            include: params
        };
    }
    generateFilters(payload) {
        let params = {};
        let search = null;
        if (payload.search) {
            let searchKey = {};
            const searchObject = Object.keys(payload.search).map((key)=>{
                let searchKeyFormatted = undefined;
                if (payload.options?.search === "equals") search = payload.search[key];
                else search = {
                    contains: payload.search[key]
                };
                // ! Verifica se o último caractere é digito para receber multiplos indexes iguais
                if (/^\d+(?:\.\d+)?$/.test(key.charAt(key.length - 1))) searchKeyFormatted = key.slice(0, -1);
                if (typeof payload.search[key] !== "string") {
                    if (key.includes(".")) {
                        const linkedKeys = key.split(".");
                        searchKey = this.generateSearchKey(linkedKeys, searchKeyFormatted, key, payload.search, payload.options?.search || "contains");
                    } else searchKey = {
                        [searchKeyFormatted || key]: payload.search[key]
                    };
                } else if (key.includes(".")) {
                    const linkedKeys = key.split(".");
                    searchKey = this.generateSearchKey(linkedKeys, searchKeyFormatted, key, payload.search, payload.options?.search || "contains");
                } else searchKey = {
                    [searchKeyFormatted || key]: search
                };
                return searchKey;
            });
            params = {
                where: {
                    [payload.options?.filter || "OR"]: searchObject
                }
            };
        }
        let orderBy = [];
        if (payload.sort) Object.keys(payload.sort).forEach((sortField)=>{
            if (sortField.includes(".")) {
                const linkedSortFields = sortField.split(".");
                orderBy.push({
                    [linkedSortFields[0]]: {
                        [linkedSortFields[1]]: payload.sort[sortField]
                    }
                });
            } else orderBy.push({
                [sortField]: payload.sort[sortField]
            });
        });
        params = {
            ...params,
            orderBy: orderBy
        };
        if (payload.pagination) params = {
            ...params,
            take: payload.pagination.take,
            skip: payload.pagination.take * (payload.pagination.page - 1)
        };
        return params;
    }
    generateSearchKey(linkedKeys, searchKeyFormatted, key, search, options) {
        let relationToSearch = undefined;
        // ! Search depth on relations
        if (linkedKeys[2]) {
            // ! Options defines if the search is about the exatcly same string or just containing the letter on their string similar to %%
            if (options === "equals") relationToSearch = {
                [searchKeyFormatted || linkedKeys[2]]: search[key]
            };
            else relationToSearch = {
                [searchKeyFormatted || linkedKeys[2]]: {
                    contains: search[key]
                }
            };
        } else // ! Options defines if the search is about the exatcly same string or just containing the letter on their string similar to %%
        if (options === "equals") relationToSearch = search[key];
        else relationToSearch = {
            contains: search[key]
        };
        return {
            [linkedKeys[0]]: {
                [linkedKeys[1]]: relationToSearch
            }
        };
    }
}





"use strict";

var $149c1bd638913645$require$Buffer = $hgUW1$Buffer;
class $149c1bd638913645$export$476e5855ddccb80c {
    modules = [
        new (0, $b19745b8f5f6cb44$export$2e2bcd8739ae039)("auth")
    ];
    constructor(modules){
        this._env = (0, $45d3915c933c04b9$export$29cd7b75162a9425).instance;
        this.modules = this.modules.concat(modules);
        this.context = this._env.config.apiContext || "api";
        this.version = this._env.config.apiVersion || "v1";
    }
    bootstrap() {
        const router = (0, $hgUW1$Router)();
        const app = (0, $hgUW1$express)();
        app.disable("x-powered-by");
        app.use((0, $hgUW1$morgan)("dev"));
        app.use((0, $hgUW1$cors)({
            allowedHeaders: [
                "Origin",
                "X-Requested-With",
                "Content-Type",
                "queue-token",
                "Accept",
                "X-Access-Token",
                "Authorization", 
            ],
            credentials: true,
            methods: "GET,HEAD,OPTIONS,PUT,PATCH,POST,DELETE",
            origin: "*",
            preflightContinue: false
        }));
        app.use((0, $hgUW1$express).json({
            limit: "300mb"
        }));
        app.use((0, $hgUW1$express).urlencoded({
            extended: true
        }));
        const moduleOcurrencies = this.modules.filter((module)=>module.moduleName === "auth");
        if (moduleOcurrencies.length > 1) this.modules.shift();
        this.modules.forEach((module)=>{
            router.use(`/${this.context}/${this.version}/${module.moduleName}`, -!module.isPublic ? (0, $e5d72593abdc7836$export$c807668e63e7354b) : (_, __, next)=>next(), module.router.router);
        });
        app.use(router);
        app.listen(this._env.config.serverPort, ()=>{
            console.log(`Server up and running on port: ${this._env.config.serverPort} `);
        }).on("error", (error)=>console.error(`Error: ${error}`));
        return app;
    }
}
class $149c1bd638913645$export$9b4c51f809ceb511 {
    folderName = "unknow";
    constructor(modules, folderName = "unknowContext"){
        this.folderName = folderName;
        this.modules = modules;
    }
    async createModules(srcDirName) {
        const moduleFiles = [];
        let files;
        if (!(0, $hgUW1$fs).existsSync(`${srcDirName}/modules`)) (0, $hgUW1$fs).mkdirSync(`${srcDirName}/modules`, {
            recursive: true
        });
        files = (0, $hgUW1$fs).readdirSync(`${srcDirName}/modules`);
        this.modules.forEach((module)=>{
            let isOk = true;
            for(const file in files)if (file === module) isOk = false;
            if (isOk) moduleFiles.push(module);
        });
        moduleFiles.forEach((moduleFile)=>{
            let modelName = moduleFile.charAt(0).toUpperCase() + moduleFile.slice(1);
            if (!(0, $hgUW1$fs).existsSync((0, $hgUW1$path).resolve(srcDirName, "modules", moduleFile))) {
                (0, $hgUW1$fs).mkdir(`${srcDirName}/modules/${moduleFile}`, {
                    recursive: true
                }, (err)=>{
                    if (err) console.error(err);
                });
                if ((0, $hgUW1$fs).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/controller-sample.txt")) {
                    let controller = (0, $hgUW1$fs).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/controller-sample.txt");
                    const controllerCode = $149c1bd638913645$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, $hgUW1$fs).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-controller.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else console.info(`${modelName} Controller File written successfully`);
                    });
                } else console.info("Controller File not written");
                if ((0, $hgUW1$fs).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/router-sample.txt")) {
                    let controller = (0, $hgUW1$fs).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/router-sample.txt");
                    const controllerCode = $149c1bd638913645$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, $hgUW1$fs).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-router.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else console.info(`${modelName} Router File written successfully`);
                    });
                } else console.info("Router File not written");
                if ((0, $hgUW1$fs).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/service-sample.txt")) {
                    let controller = (0, $hgUW1$fs).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/service-sample.txt");
                    const controllerCode = $149c1bd638913645$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, $hgUW1$fs).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-service.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else console.info(`${modelName} Service File written successfully`);
                    });
                } else console.info("Service File not written");
                if ((0, $hgUW1$fs).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/repository-sample.txt")) {
                    let controller = (0, $hgUW1$fs).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/repository-sample.txt");
                    const controllerCode = $149c1bd638913645$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, $hgUW1$fs).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-repository.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else console.info(`${modelName} Repository File written successfully`);
                    });
                } else console.info("Repository File not written");
                if ((0, $hgUW1$fs).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/module-sample.txt")) {
                    let controller = (0, $hgUW1$fs).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/module-sample.txt");
                    const controllerCode = $149c1bd638913645$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, $hgUW1$fs).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-module.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else console.info(`${modelName} Module File written successfully`);
                    });
                } else console.info("Module File not written");
                if ((0, $hgUW1$fs).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/interfaces-sample.txt")) {
                    let controller = (0, $hgUW1$fs).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/interfaces-sample.txt");
                    const controllerCode = $149c1bd638913645$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, $hgUW1$fs).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-interfaces.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else {
                            console.info(`${modelName} Interfaces File written successfully`);
                            console.info("\n-----------------------------------------------------------------\n");
                        }
                    });
                } else {
                    console.info("Interfaces File not written");
                    console.info("\n-----------------------------------------------------------------\n");
                }
            }
        });
    }
    removeModule(srcDirName, name) {
        if ((0, $hgUW1$fs).existsSync(`${srcDirName}/modules/${name}`)) (0, $hgUW1$fs).rmdir(`${srcDirName}/modules/${name}`, {
            recursive: true
        }, (error)=>{
            if (error) console.error(error);
            else console.log("Folder Deleted!");
        });
    }
}


export {$149c1bd638913645$export$476e5855ddccb80c as PullupModules, $149c1bd638913645$export$9b4c51f809ceb511 as StartModules, $9efd3723d3141683$export$7221f9f9609a7e93 as onSuccess, $9efd3723d3141683$export$2288787135a8f66e as onError, $f068a559611004a3$export$98f03c5d19621d70 as Global, $7f1901e1d291bb3f$export$1cea2e25b75a88f2 as sendEmail, $e5d72593abdc7836$export$c807668e63e7354b as verifyToken, $be423279252da9d8$export$6bfa95453d427b2b as BadRequestError, $be423279252da9d8$export$cf0c46b07324e9c5 as AuthenticationError, $be423279252da9d8$export$6d7c35f6d47c9072 as ForbiddenError, $be423279252da9d8$export$78c95b58762d2106 as NotFoundError, $be423279252da9d8$export$d191fb0a9d005daf as UnprocessableEntityError};
//# sourceMappingURL=index.es.js.map

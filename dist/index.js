var $8zHUo$fs = require("fs");
var $8zHUo$express = require("express");
var $8zHUo$cors = require("cors");
var $8zHUo$morgan = require("morgan");
var $8zHUo$path = require("path");
var $8zHUo$buffer = require("buffer");
var $8zHUo$prismaclient = require("@prisma/client");
var $8zHUo$jsonwebtoken = require("jsonwebtoken");
var $8zHUo$process = require("process");
var $8zHUo$bcrypt = require("bcrypt");
var $8zHUo$yup = require("yup");
var $8zHUo$nodemailer = require("nodemailer");

function $parcel$interopDefault(a) {
  return a && a.__esModule ? a.default : a;
}
function $parcel$export(e, n, v, s) {
  Object.defineProperty(e, n, {get: v, set: s, enumerable: true, configurable: true});
}
function $parcel$exportWildcard(dest, source) {
  Object.keys(source).forEach(function(key) {
    if (key === 'default' || key === '__esModule' || dest.hasOwnProperty(key)) {
      return;
    }

    Object.defineProperty(dest, key, {
      enumerable: true,
      get: function get() {
        return source[key];
      }
    });
  });

  return dest;
}

$parcel$export(module.exports, "PullupModules", () => $882b6d93070905b3$export$476e5855ddccb80c);
$parcel$export(module.exports, "StartModules", () => $882b6d93070905b3$export$9b4c51f809ceb511);
$parcel$export(module.exports, "onSuccess", () => $2858fa56817a9b00$export$7221f9f9609a7e93);
$parcel$export(module.exports, "onError", () => $2858fa56817a9b00$export$2288787135a8f66e);
$parcel$export(module.exports, "Global", () => $592c08bc44885ff8$export$98f03c5d19621d70);
$parcel$export(module.exports, "sendEmail", () => $b52943c4d599c25d$export$1cea2e25b75a88f2);
$parcel$export(module.exports, "verifyToken", () => $a5de8b3d1704b73b$export$c807668e63e7354b);





class $b116e86cb84fcfa5$export$2e2bcd8739ae039 {
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





class $d59703d51e70fab0$export$29cd7b75162a9425 {
    static get instance() {
        if (!$d59703d51e70fab0$export$29cd7b75162a9425._instance) $d59703d51e70fab0$export$29cd7b75162a9425._instance = new $d59703d51e70fab0$export$29cd7b75162a9425();
        return $d59703d51e70fab0$export$29cd7b75162a9425._instance;
    }
    get config() {
        return this._config;
    }
    constructor(){
        this._config = this.readConfigFile();
    }
    readConfigFile() {
        let config = null;
        if ($8zHUo$process.cwd().includes("dist")) config = (0, ($parcel$interopDefault($8zHUo$fs))).readFileSync((0, ($parcel$interopDefault($8zHUo$path))).resolve("../config.json"));
        else config = (0, ($parcel$interopDefault($8zHUo$fs))).readFileSync((0, ($parcel$interopDefault($8zHUo$path))).resolve("config.json"));
        return JSON.parse(config.toString());
    }
}


var $66bc8d4f40b5480e$exports = {};

$parcel$export($66bc8d4f40b5480e$exports, "BadRequestError", () => $66bc8d4f40b5480e$export$6bfa95453d427b2b);
$parcel$export($66bc8d4f40b5480e$exports, "AuthenticationError", () => $66bc8d4f40b5480e$export$cf0c46b07324e9c5);
$parcel$export($66bc8d4f40b5480e$exports, "ForbiddenError", () => $66bc8d4f40b5480e$export$6d7c35f6d47c9072);
$parcel$export($66bc8d4f40b5480e$exports, "NotFoundError", () => $66bc8d4f40b5480e$export$78c95b58762d2106);
$parcel$export($66bc8d4f40b5480e$exports, "UnprocessableEntityError", () => $66bc8d4f40b5480e$export$d191fb0a9d005daf);
class $66bc8d4f40b5480e$export$6bfa95453d427b2b extends Error {
    constructor(message){
        super(message);
        this._status = 400;
    }
    get status() {
        return this._status;
    }
}
class $66bc8d4f40b5480e$export$cf0c46b07324e9c5 extends Error {
    constructor(message){
        super(message);
        this._status = 401;
    }
    get status() {
        return this._status;
    }
}
class $66bc8d4f40b5480e$export$6d7c35f6d47c9072 extends Error {
    constructor(message){
        super(message);
        this._status = 403;
    }
    get status() {
        return this._status;
    }
}
class $66bc8d4f40b5480e$export$78c95b58762d2106 extends Error {
    constructor(message){
        super(message);
        this._status = 404;
    }
    get status() {
        return this._status;
    }
}
class $66bc8d4f40b5480e$export$d191fb0a9d005daf extends Error {
    constructor(message){
        super(message);
        this._status = 422;
    }
    get status() {
        return this._status;
    }
}


function $2858fa56817a9b00$export$2288787135a8f66e(response, error) {
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
function $2858fa56817a9b00$export$7221f9f9609a7e93(response, statusCode, data) {
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


const $a5de8b3d1704b73b$var$env = (0, $d59703d51e70fab0$export$29cd7b75162a9425).instance;
const $a5de8b3d1704b73b$var$userRepository = new (0, $b116e86cb84fcfa5$export$2e2bcd8739ae039)(new (0, $8zHUo$prismaclient.PrismaClient)());
async function $a5de8b3d1704b73b$export$c807668e63e7354b(request, response, next) {
    try {
        const token = request.headers.authorization?.replace("Bearer ", "");
        const decodedToken = (0, ($parcel$interopDefault($8zHUo$jsonwebtoken))).verify(token, `${$a5de8b3d1704b73b$var$env.config.jwtSecret}`);
        const dbUser = await $a5de8b3d1704b73b$var$userRepository.findByEmail(`${decodedToken.payload}`);
        if (!dbUser) throw new (0, $66bc8d4f40b5480e$export$cf0c46b07324e9c5)("Usu\xe1rio inv\xe1lido!");
        request.user = dbUser;
        next();
    } catch (error) {
        return (0, $2858fa56817a9b00$export$2288787135a8f66e)(response, error);
    }
}














"use strict";
const $b52943c4d599c25d$var$env = (0, $d59703d51e70fab0$export$29cd7b75162a9425).instance;
const $b52943c4d599c25d$var$transport = (0, ($parcel$interopDefault($8zHUo$nodemailer))).createTransport({
    host: $b52943c4d599c25d$var$env.config.smtpHost,
    port: $b52943c4d599c25d$var$env.config.smtpPort,
    secure: $b52943c4d599c25d$var$env.config.smtpSecure,
    auth: {
        user: $b52943c4d599c25d$var$env.config.smtpUser,
        pass: $b52943c4d599c25d$var$env.config.smtpPass
    },
    tls: {
        ciphers: "SSLv3"
    }
});
async function $b52943c4d599c25d$export$1cea2e25b75a88f2(emailTo, subject, html) {
    try {
        const info = await $b52943c4d599c25d$var$transport.sendMail({
            from: $b52943c4d599c25d$var$env.config.mailFrom,
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





var $93471a37b9fb8a10$var$__dirname = "src/modules/auth";
const $93471a37b9fb8a10$var$env = (0, $d59703d51e70fab0$export$29cd7b75162a9425).instance;
class $93471a37b9fb8a10$export$2e2bcd8739ae039 {
    constructor(prismaClient){
        this.prismaClient = prismaClient;
        this.authRepository = new (0, $b116e86cb84fcfa5$export$2e2bcd8739ae039)(prismaClient);
    }
    _generateAuthToken(email, expiresIn = "24h") {
        return (0, ($parcel$interopDefault($8zHUo$jsonwebtoken))).sign({
            payload: email
        }, $93471a37b9fb8a10$var$env.config.jwtSecret, {
            expiresIn: expiresIn
        });
    }
    async login(payload) {
        const userSchema = $8zHUo$yup.object({
            email: $8zHUo$yup.string().email().required(),
            password: $8zHUo$yup.string().min(8).required()
        });
        const validatedData = await userSchema.validate(payload);
        const user1 = await this.authRepository.findByEmail(validatedData.email);
        if (!user1) throw new (0, $66bc8d4f40b5480e$export$cf0c46b07324e9c5)("Usu\xe1rio inv\xe1lido!");
        // @ts-expect-error
        if (user1 && (user1.deletedAt || !user1.active)) throw new (0, $66bc8d4f40b5480e$export$6d7c35f6d47c9072)("Usu\xe1rio inv\xe1lido!");
        const isPasswordValid = await (0, ($parcel$interopDefault($8zHUo$bcrypt))).compare(validatedData.password, user1.password);
        if (!isPasswordValid) throw new (0, $66bc8d4f40b5480e$export$cf0c46b07324e9c5)("Usu\xe1rio inv\xe1lido!");
        const { password: password , ...userResponse } = user1;
        return {
            token: this._generateAuthToken(user1.email),
            user: userResponse
        };
    }
    async register(payload) {
        const userSchema = $8zHUo$yup.object({
            name: $8zHUo$yup.string().min(3).required(),
            email: $8zHUo$yup.string().email().required(),
            password: $8zHUo$yup.string().min(8).required(),
            roleId: $8zHUo$yup.number().required()
        });
        const validatedData = await userSchema.validate(payload);
        const isRegistered = await this.authRepository.findByEmail(validatedData.email);
        if (isRegistered) throw new (0, $66bc8d4f40b5480e$export$cf0c46b07324e9c5)("Usu\xe1rio inv\xe1lido!");
        const salt = await (0, ($parcel$interopDefault($8zHUo$bcrypt))).genSalt();
        const hashPassword = await (0, ($parcel$interopDefault($8zHUo$bcrypt))).hash(validatedData.password, salt);
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
        const userSchema = $8zHUo$yup.object({
            email: $8zHUo$yup.string().email().required()
        });
        const validatedData = await userSchema.validate(email);
        const user2 = await this.authRepository.findByEmail(validatedData.email);
        if (!user2) throw new (0, $66bc8d4f40b5480e$export$cf0c46b07324e9c5)("Usu\xe1rio inv\xe1lido!");
        const template = (0, ($parcel$interopDefault($8zHUo$fs))).readFileSync((0, ($parcel$interopDefault($8zHUo$path))).resolve($93471a37b9fb8a10$var$__dirname, "../../templates/forgot-password.html"));
        const token = this._generateAuthToken(user2.email, "1h");
        const success = this.authRepository.saveConfirmationCode(user2.id, token);
        if (!success) throw new (0, $66bc8d4f40b5480e$export$d191fb0a9d005daf)("Erro ao processar solicita\xe7\xe3o");
        let emailBody = template.toString().replace("{{FRONT_URL}}", $93471a37b9fb8a10$var$env.config.frontURL).replace("{{TOKEN}}", `${token}`).replace("{{NAME}}", `${user2.name}`).replace("{{EMAIL}}", `${validatedData.email}`);
        const message = await (0, $b52943c4d599c25d$export$1cea2e25b75a88f2)(user2.email, "Esqueci Minha Senha", emailBody);
        return message;
    }
    async me(requestUser) {
        const dbUser = await this.authRepository.findByEmail(requestUser.email);
        if (!dbUser) throw new (0, $66bc8d4f40b5480e$export$78c95b58762d2106)("Usu\xe1rio n\xe3o encontrado!");
        // @ts-ignore
        const { password: password , confirmationCode: confirmationCode , ...userResponse } = dbUser;
        return {
            user: userResponse
        };
    }
    async updatePassword(payload) {
        const userSchema = $8zHUo$yup.object({
            newPassword: $8zHUo$yup.string().min(8).required(),
            newPasswordConfirmation: $8zHUo$yup.string().min(8).required(),
            confirmationCode: $8zHUo$yup.string().required()
        });
        const validatedData = await userSchema.validate(payload);
        if (validatedData.newPassword !== validatedData.newPasswordConfirmation) throw new (0, $66bc8d4f40b5480e$export$6bfa95453d427b2b)("Senha inv\xe1lida!");
        const decodedToken = (0, ($parcel$interopDefault($8zHUo$jsonwebtoken))).verify(validatedData.confirmationCode, $93471a37b9fb8a10$var$env.config.jwtSecret);
        const user3 = await this.authRepository.findByConfirmationCode(validatedData.confirmationCode);
        if (!decodedToken || !user3) throw new (0, $66bc8d4f40b5480e$export$6bfa95453d427b2b)("C\xf3digo inv\xe1lido!");
        await this.authRepository.saveConfirmationCode(user3.id, null);
        const salt = await (0, ($parcel$interopDefault($8zHUo$bcrypt))).genSalt();
        const hashPassword = await (0, ($parcel$interopDefault($8zHUo$bcrypt))).hash(validatedData.newPassword, salt);
        const isPassSaved = await this.authRepository.updatePassword(user3.id, hashPassword);
        if (!isPassSaved) throw new (0, $66bc8d4f40b5480e$export$d191fb0a9d005daf)("Senha Inv\xe1lida!");
        return `Senha atualizada com sucesso!`;
    }
    async resetPassword(payload) {
        const userSchema = $8zHUo$yup.object({
            newPassword: $8zHUo$yup.string().min(8).required(),
            email: $8zHUo$yup.string().required()
        });
        const validatedData = await userSchema.validate(payload);
        const user4 = await this.authRepository.findByEmail(validatedData.email);
        if (!user4) throw new (0, $66bc8d4f40b5480e$export$6bfa95453d427b2b)("Usu\xe1rio inv\xe1lido!");
        const salt = await (0, ($parcel$interopDefault($8zHUo$bcrypt))).genSalt();
        const hashPassword = await (0, ($parcel$interopDefault($8zHUo$bcrypt))).hash(validatedData.newPassword, salt);
        const isPassSaved = await this.authRepository.updatePassword(user4.id, hashPassword);
        if (!isPassSaved) throw new (0, $66bc8d4f40b5480e$export$d191fb0a9d005daf)("Senha Inv\xe1lida!");
        return `Senha atualizada com sucesso!`;
    }
}


class $7a590667595df199$export$2e2bcd8739ae039 {
    constructor(prismaClient){
        this.prismaClient = prismaClient;
        this.service = new (0, $93471a37b9fb8a10$export$2e2bcd8739ae039)(prismaClient);
    }
    async login(request, response) {
        try {
            const loginResponse = await this.service.login(request.body);
            return (0, $2858fa56817a9b00$export$7221f9f9609a7e93)(response, 200, loginResponse);
        } catch (error) {
            return (0, $2858fa56817a9b00$export$2288787135a8f66e)(response, error);
        }
    }
    async register(request, response) {
        try {
            const user = await this.service.register(request.body);
            return (0, $2858fa56817a9b00$export$7221f9f9609a7e93)(response, 201, user);
        } catch (error) {
            return (0, $2858fa56817a9b00$export$2288787135a8f66e)(response, error);
        }
    }
    async me(request, response) {
        try {
            const user = await this.service.me(request.user);
            return (0, $2858fa56817a9b00$export$7221f9f9609a7e93)(response, 200, user);
        } catch (error) {
            return (0, $2858fa56817a9b00$export$2288787135a8f66e)(response, error);
        }
    }
    async forgotPassword(request, response) {
        try {
            const message = await this.service.forgotPassword(request.body);
            return (0, $2858fa56817a9b00$export$7221f9f9609a7e93)(response, 200, {
                message: message
            });
        } catch (error) {
            return (0, $2858fa56817a9b00$export$2288787135a8f66e)(response, error);
        }
    }
    async updatePassword(request, response) {
        try {
            const message = await this.service.updatePassword(request.body);
            return (0, $2858fa56817a9b00$export$7221f9f9609a7e93)(response, 200, {
                message: message
            });
        } catch (error) {
            return (0, $2858fa56817a9b00$export$2288787135a8f66e)(response, error);
        }
    }
    async resetPassword(request, response) {
        try {
            const message = await this.service.resetPassword(request.body);
            return (0, $2858fa56817a9b00$export$7221f9f9609a7e93)(response, 200, {
                message: message
            });
        } catch (error) {
            return (0, $2858fa56817a9b00$export$2288787135a8f66e)(response, error);
        }
    }
}


class $ebd5a17fa3eb73dd$export$2e2bcd8739ae039 {
    constructor(prismaClient){
        this.prismaClient = prismaClient;
        this.router = (0, $8zHUo$express.Router)();
        this.controller = new (0, $7a590667595df199$export$2e2bcd8739ae039)(prismaClient);
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
        this.router.get("/me", (0, $a5de8b3d1704b73b$export$c807668e63e7354b), (request, response)=>{
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



class $a69821f930cb52f2$export$2e2bcd8739ae039 {
    isPublic = true;
    constructor(moduleName){
        this.moduleName = moduleName;
        this.router = new (0, $ebd5a17fa3eb73dd$export$2e2bcd8739ae039)(new (0, $8zHUo$prismaclient.PrismaClient)());
        this.loadRoutes();
    }
    loadRoutes() {
        this.router.login().register().forgotPassword().updatePassword().me().resetPassword();
    }
}





class $592c08bc44885ff8$export$98f03c5d19621d70 {
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

var $882b6d93070905b3$require$Buffer = $8zHUo$buffer.Buffer;
class $882b6d93070905b3$export$476e5855ddccb80c {
    modules = [
        new (0, $a69821f930cb52f2$export$2e2bcd8739ae039)("auth")
    ];
    constructor(modules){
        this._env = (0, $d59703d51e70fab0$export$29cd7b75162a9425).instance;
        this.modules = this.modules.concat(modules);
        this.context = this._env.config.apiContext || "api";
        this.version = this._env.config.apiVersion || "v1";
    }
    bootstrap() {
        const router = (0, $8zHUo$express.Router)();
        const app = (0, ($parcel$interopDefault($8zHUo$express)))();
        app.disable("x-powered-by");
        app.use((0, ($parcel$interopDefault($8zHUo$morgan)))("dev"));
        app.use((0, ($parcel$interopDefault($8zHUo$cors)))({
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
        app.use((0, ($parcel$interopDefault($8zHUo$express))).json({
            limit: "300mb"
        }));
        app.use((0, ($parcel$interopDefault($8zHUo$express))).urlencoded({
            extended: true
        }));
        const moduleOcurrencies = this.modules.filter((module)=>module.moduleName === "auth");
        if (moduleOcurrencies.length > 1) this.modules.shift();
        this.modules.forEach((module)=>{
            router.use(`/${this.context}/${this.version}/${module.moduleName}`, -!module.isPublic ? (0, $a5de8b3d1704b73b$export$c807668e63e7354b) : (_, __, next)=>next(), module.router.router);
        });
        app.use(router);
        app.listen(this._env.config.serverPort, ()=>{
            console.log(`Server up and running on port: ${this._env.config.serverPort} `);
        }).on("error", (error)=>console.error(`Error: ${error}`));
        return app;
    }
}
class $882b6d93070905b3$export$9b4c51f809ceb511 {
    folderName = "unknow";
    constructor(modules, folderName = "unknowContext"){
        this.folderName = folderName;
        this.modules = modules;
    }
    async createModules(srcDirName) {
        const moduleFiles = [];
        let files;
        if (!(0, ($parcel$interopDefault($8zHUo$fs))).existsSync(`${srcDirName}/modules`)) (0, ($parcel$interopDefault($8zHUo$fs))).mkdirSync(`${srcDirName}/modules`, {
            recursive: true
        });
        files = (0, ($parcel$interopDefault($8zHUo$fs))).readdirSync(`${srcDirName}/modules`);
        this.modules.forEach((module)=>{
            let isOk = true;
            for(const file in files)if (file === module) isOk = false;
            if (isOk) moduleFiles.push(module);
        });
        moduleFiles.forEach((moduleFile)=>{
            let modelName = moduleFile.charAt(0).toUpperCase() + moduleFile.slice(1);
            if (!(0, ($parcel$interopDefault($8zHUo$fs))).existsSync((0, ($parcel$interopDefault($8zHUo$path))).resolve(srcDirName, "modules", moduleFile))) {
                (0, ($parcel$interopDefault($8zHUo$fs))).mkdir(`${srcDirName}/modules/${moduleFile}`, {
                    recursive: true
                }, (err)=>{
                    if (err) console.error(err);
                });
                if ((0, ($parcel$interopDefault($8zHUo$fs))).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/controller-sample.txt")) {
                    let controller = (0, ($parcel$interopDefault($8zHUo$fs))).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/controller-sample.txt");
                    const controllerCode = $882b6d93070905b3$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, ($parcel$interopDefault($8zHUo$fs))).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-controller.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else console.info(`${modelName} Controller File written successfully`);
                    });
                } else console.info("Controller File not written");
                if ((0, ($parcel$interopDefault($8zHUo$fs))).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/router-sample.txt")) {
                    let controller = (0, ($parcel$interopDefault($8zHUo$fs))).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/router-sample.txt");
                    const controllerCode = $882b6d93070905b3$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, ($parcel$interopDefault($8zHUo$fs))).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-router.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else console.info(`${modelName} Router File written successfully`);
                    });
                } else console.info("Router File not written");
                if ((0, ($parcel$interopDefault($8zHUo$fs))).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/service-sample.txt")) {
                    let controller = (0, ($parcel$interopDefault($8zHUo$fs))).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/service-sample.txt");
                    const controllerCode = $882b6d93070905b3$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, ($parcel$interopDefault($8zHUo$fs))).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-service.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else console.info(`${modelName} Service File written successfully`);
                    });
                } else console.info("Service File not written");
                if ((0, ($parcel$interopDefault($8zHUo$fs))).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/repository-sample.txt")) {
                    let controller = (0, ($parcel$interopDefault($8zHUo$fs))).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/repository-sample.txt");
                    const controllerCode = $882b6d93070905b3$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, ($parcel$interopDefault($8zHUo$fs))).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-repository.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else console.info(`${modelName} Repository File written successfully`);
                    });
                } else console.info("Repository File not written");
                if ((0, ($parcel$interopDefault($8zHUo$fs))).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/module-sample.txt")) {
                    let controller = (0, ($parcel$interopDefault($8zHUo$fs))).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/module-sample.txt");
                    const controllerCode = $882b6d93070905b3$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, ($parcel$interopDefault($8zHUo$fs))).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-module.ts`, controllerCode, (err)=>{
                        if (err) console.error(err);
                        else console.info(`${modelName} Module File written successfully`);
                    });
                } else console.info("Module File not written");
                if ((0, ($parcel$interopDefault($8zHUo$fs))).existsSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/interfaces-sample.txt")) {
                    let controller = (0, ($parcel$interopDefault($8zHUo$fs))).readFileSync(srcDirName + "/node_modules/@pablo-dav/modular-api/samples/interfaces-sample.txt");
                    const controllerCode = $882b6d93070905b3$require$Buffer.from(controller).toString().replace(/{{MODULE_NAME}}/g, moduleFile).replace(/{{MODEL_NAME}}/g, modelName);
                    (0, ($parcel$interopDefault($8zHUo$fs))).writeFile(`${srcDirName}/modules/${moduleFile}/${moduleFile}-interfaces.ts`, controllerCode, (err)=>{
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
        if ((0, ($parcel$interopDefault($8zHUo$fs))).existsSync(`${srcDirName}/modules/${name}`)) (0, ($parcel$interopDefault($8zHUo$fs))).rmdir(`${srcDirName}/modules/${name}`, {
            recursive: true
        }, (error)=>{
            if (error) console.error(error);
            else console.log("Folder Deleted!");
        });
    }
}
$parcel$exportWildcard(module.exports, $66bc8d4f40b5480e$exports);


//# sourceMappingURL=index.js.map

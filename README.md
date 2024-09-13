# Modular API

## Descrição

// Biblioteca para gerenciamento e criação de módulos baseados em uma entidade do sistema para criar um CRUD inicial utilizando repository pattern para melhor gerenciamento de acoplamento e criação de endpoints em uma API REST.

## Tecnologias

A Modular API foi criada utilizando essas tecnologias base:

1 - Node.js;
2 - Typescript;
3 - Express;
4 - Prisma ORM;

E sendo baseado principalmente no Nest.JS e Orion uma biblioteca do Laravel.

## Pré-requisitos

Para executar Modular API, é necessário ter o node em sua versão maior ou igual a `v18.17.0`.

### Configuração do Ambiente

Instale a biblioteca via npm:
Comando -> `npm install "@pablo-dav/modular-api" express "@prisma/client@4.14.1" copyfiles`
Comando -> `npm install -D nodemon prisma ts-node`

configure os seguintes scripts no seu package.json:

"scripts": {
"setup": "ts-node setup.ts",
"dev": "nodemon",
"build": "tsc && copyfiles src/templates/\*.html dist/",
}

caso não esteja utilizando typescript, não é necessário compilar ou utilizar as dependencias `ts-node copyfiles`:

"scripts": {
"setup": "node setup.ts",
"dev": "nodemon",
}

### Executando o projeto

Para executar o servidor de desenvolvimento, utilize a seguinte arquitetura:

-- /modules
com um arquivo index.ts ou index.js com o seguinte formato:
import AuthModule from "./auth/auth-module";

const prismaClient = new PrismaClient();

export const modules = [
new AuthModule(moduleName: string, isPublic: boolean, prismaClient: PrismaClient),
]

-- /src/templates (caso precise de envio de e-mail coloque um template html com um link na estrutura nesse formato `{{FRONT_URL}}/?confirmation_code={{TOKEN}}`
-- /modules
-- index.js / index.ts
// index example

import { ApiModules } from "@pablo-dav/modular-api";
import { modules } from "./modules";

const modularApi = new ApiModules(modules);

modularApi.bootstrap();

-- setup.js / setup.ts

// setup example
import { StartModules } from "@pablo-dav/modular-api";

const client = new StartModules(Object.keys(
{
auth: "auth",
}
));

client.createModules(\_\_dirname);

-- config.json

// config.json example
{
"apiContext": "",
"apiVersion": "",
"serverPort": 0,
"smtpHost": "",
"smtpPort": 0,
"smtpSecure": false,
"smtpUser": "",
"smtpPass": "",
"mailFrom": "",
"frontURL": "",
"jwtSecret": "",
"defaultPassword": ""
}

npm run setup vai gerar os modulos adicionados no arquivo de setup

e ao final:
npm run dev

### Consideracoes

Para aprender mais sobre o as ferramentas utilizadas, confira os recursos a seguir:
https://nestjs.com
https://orion.tailflow.org

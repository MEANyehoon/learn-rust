# Structuring Rust Projects for Testability

原文地址： https://betterprogramming.pub/structuring-rust-project-for-testability-18207b5d0243


在这篇文章中，我们会看到如何组织一个容易测试的Rust项目的结构。我们会实现一个简单的验证模块。
该模块对外通过REST API暴露，使用PostgreSQL和Redis存储数据。使用actix-web处理REST API部分，使用sqlx和PostgreSQL交互，使用redis-rs和Redis交互。我们会看到如何将该模块分解为容易测试的一个个小组件。最终版本的源代码可以在GitHub查看。



# 背景

大家都知道，在软件项目中加入自动化测试，可以使软件变的更好。自动化测试帮助我们确定软件的正确性和提高软件的可维护性。所以在软件项目中加入自动化测试是一个好的实践。

不幸的是，加入自动化测试不是一个简单的事情。你得思考怎么组织项目结构，让它容易测试。也就是说，你需要将软件模块化，将软件分割成可以独立测试的，解耦的一个个小组件。

我是在开发一个Rust web项目时发现的这个问题。我尝试从一些开源的项目里找灵感。遗憾的是，这些开源项目的自动化测试程度远远没有达到我的预期。大多数都跳过了单元测试，只是简单的进行一些集成测试，有的甚至没有集成测试。

写这篇文章的目的是向你分享一种用来解决上边提到的问题的方案。希望大家认为这有用。另外我非常高兴接收大家对于如何组织你的Rust项目的反馈，这样我也可以扩充我的Rust“工具箱”。

# 端口适配器模式(Ports-and-Adapters Pattern)
*我对于Web类型软件项目以外的经验有限，请谨慎对待本节内容*

大多数软件可以使用端口适配器模式来组织。在这个模式下，通过以下几种组件类型来组织项目结构。

1. **Domain(领域):** 负责处理领域专有的逻辑。比如说，如果你的领域是银行，domain组件负责银行领域特有的功能。例如在两个账号之间转账。

2. **Ports(端口):** 表示外部系统和你的领域交互的“契约”，无论是从外到內，还是从内到外。

3. **Adapters(适配器):** 这些组件“适配”外部系统到你的Ports。比如说，一个适配器将HTTP请求适配到了Ports提供的操作上。又比如说，一个适配器将端口适配到了一个SQL数据库提供的行为上。

4. **Application(应用层)** 这个类型的组件组织了所有其他的组件。端口适配器模式的一个好处是，我们可以为同一个端口提供不同的适配器。比如说，你可以通过REST API或者命令行和你的Domain交互，只需要为他们分别实现不同的适配器就可以了。当Application组织这些组件的时候，它就可以决定，具体使用哪个适配器。

![端口适配器模式](./ports_and_adapters_pattern.png)


当我们使用上述的组件类型来组织项目，我们就可以通过[**test double**](https://en.wikipedia.org/wiki/Test_double)的帮助来进行单独的测试。比如说，你想测试一个领域逻辑，当端口触发了一个特定领域逻辑，是否返回了期望得到的返回值。又比如说，测试一个HTTP适配器，一个HTTP请求是否会触发正确的端口。

![在端口适配器模式下测试各个组件的策略](./test_each_component.png)

# Rust中的例子
我们现在已经有了一些基本概念，让我们看看如何应用在Rust项目上。通过例子可以更好的学习，所以现在我们来创建一个。

## 应用描述
我们要做的应用，是一个简单的权限认证模块。这个模块有以下几个功能：

1. 注册：新用户可以注册到应用中

2. 登录：已经注册的用户，可以通过提供身份信息来登录，会收到一个token用于之后请求的鉴权。

3. 鉴权：将一个token映射到一个用户

我们想要可以通过web来访问该应用。也想通过PostgreSQL来存储用户数据。想通过redis存储用户token。这些看起来都很基础。

## 架构
在端口适配器模式下，组件会按照如下设计。

### 端口(Ports)
1. **AuthService:** 暴露领域功能的端口
2. **TokenRepo:** 领域和token持久化交互的端口
3. **CredentialRepo** 领域和身份信息持久化交互的端口

### 领域层(Domain)
1. **AuthServiceImpl:** 该组件实现AuthService Port。该实现里边有认证相关的特定逻辑。

### 适配器(Adapters)
1. **RedisTokenRepo:** 该组件实现TokenRepo Port，和redis交互。将TokenRepo Port中的方法翻译为Redis的操作。

2. **PostgresCredentialRepo:** 该组件实现CredentialRepo Port,和PostgresSQL交互。将CredentialRepo Port中的方法翻译为对PostgresSQL的操作。

3. **RestAuthController:** 该组件和AuthService Port交互，在一个HTTP请求的处理中，调用AuthService Port。

### 应用层(Application)
1. **Main:** 将所有组件聚合在一起，使他们正确的工作，形成一个应用。

![应用结构](./application_structure.png)

## **Rust实现**
如何把上边的架构在Rust中实现呢？

通常的经验是用`trait`s实现Ports，其他的用`struct`s,`impl`s或者`module`s来实现。让我们一步一步来实现。

首先，我们来看一下源代码的结构。

```
.
├── Cargo.toml
├── migrations
│ └── 000000_init.sql
├── src
│ ├── auth
│ │ ├── auth_service_impl.rs
│ │ ├── mod.rs
│ │ ├── ports.rs
│ │ ├── postgres_credential_repo.rs
│ │ ├── redis_token_repo.rs
│ │ └── rest_auth_controller.rs
│ ├── infrastructure
│ │ ├── mod.rs
│ │ ├── postgresql.rs
│ │ └── redis.rs
│ └── main.rs
└── test-stack.yml
```

## **Rust中端口(Ports)的实现**
端口(Ports)定义在`auth/ports`中。你可以看到每个port都有一个`trait`，每个用于和port交互的数据结构都有一个`struct`

```rust
use async_trait::async_trait;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Credential {
    pub username: String,
    pub password: String
}

pub type Token = String;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AuthService {
    async fn register(&self, credential: &Credential) -> bool;
    async fn login(&self, credential: &Credential) -> Option<Token>;
    async fn authenticate(&self, token: &Token) -> Option<String>;
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CredentialRepo {
    async fn save_credential(&self, credential: &Credential) -> bool;
    async fn is_credential_exists(&self, credential: &Credential) -> bool;
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TokenRepo {
    async fn generate_token(&self) -> Token;
    async fn save_token(&self, token: &Token, username: &String) -> bool;
    async fn get_username_by_token(&self, token: &Token) -> Option<String>;
}
```

## **Rust中领域(Domain)的实现**
在另一个文件`auth/auth_service_impl.rs`中的`AuthServiceImpl`作为Domain组件。你可以看到在一个`struct`中持有了`TokenRepo` port和`CredentialRepo` port的引用。在实现AuthServiceImpl逻辑时，我们需要使用这些引用来和port进行交互。

你还会发现在`login`功能里有一些有趣的交互，在处理分支逻辑的时候，同时与`TokenRepo`和`CredentialRepo`进行了交互。

```rust
use super::ports::*;
use async_trait::async_trait;

pub struct AuthServiceImpl<A: CredentialRepo, B: TokenRepo> {
    pub credential_repo: A,
    pub token_repo: B,
}

#[async_trait]
impl <A, B> AuthService for AuthServiceImpl<A, B>
    where A: CredentialRepo + Sync + Send,
          B: TokenRepo + Sync + Send {

    async fn register(self: &Self, credential: &Credential) -> bool {
        self.credential_repo.save_credential(credential).await
    }

    async fn login(self: &Self, credential: &Credential) -> Option<Token> {
        if !self.credential_repo.is_credential_exists(credential).await {
            return None;
        }

        let token = self.token_repo.generate_token().await;
        if !self.token_repo.save_token(&token, &credential.username).await {
            return None;
        }

        Some(token)
    }

    async fn authenticate(self: &Self, token: &Token) -> Option<String> {
        self.token_repo.get_username_by_token(token).await
    }
}
```

在测试部分，我们只测试`login`功能，因为其它功能非常简单。我们为`TokenRepo`和`CredentialRepo`mock了测试替身。这些mock允许我们为Ports模拟各种不同的响应来验证`login`功能的正确性。我们通过`mockall`库来实现这些mock,之前已经在Port `trait`上标明了`#[cfg_attr(test, mockall::automock)]`.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;

    #[actix_web::main]
    #[test]
    async fn test_login_success() {
        let credential = Credential { username: "u".to_string(), password: "p".to_string() };
        let token = "token".to_string();

        let mut credential_repo = MockCredentialRepo::new();
        credential_repo.expect_is_credential_exists()
            .with(eq(credential.clone()))
            .return_const(true);

        let mut token_repo = MockTokenRepo::new();
        token_repo.expect_generate_token()
            .return_const(token.clone());
        token_repo.expect_save_token()
            .with(eq(token.clone()), eq(credential.username.clone()))
            .return_const(true);

        let sut = AuthServiceImpl { credential_repo, token_repo };

        let actual = sut.login(&credential).await;
        let expected = Some(token.clone());
        assert_eq!(expected, actual);
    }
	
	// Other tests are omitted for brevity
}
```

## **Rust中适配器(Adapters)的实现**
适配器(Adapters)的实现在另外几个文件中：`auth/redis_token_repo.rs`,`auth/postgres_credential_repo.rs`,`auth/rest_auth_controller.rs`

`RedisTokenRepo`实现了`TokenRepo` `trait`.持有了一个Redis Client库的引用，用来和Redis交互。测试的时候，我们用真实情况来测试：一个运行在本地的Redis实例。我们通过docker来提供Redis实例，这样比较方便。


```rust
use super::ports::*;
use async_trait::async_trait;
use uuid::Uuid;
use redis::AsyncCommands;
use std::sync::Arc;

pub struct RedisTokenRepoImpl {
    pub redis_client: Arc<redis::Client>
}

#[async_trait]
impl TokenRepo for RedisTokenRepoImpl {

    async fn generate_token(self: &Self) -> Token {
        Uuid::new_v4().to_string()
    }

    async fn save_token(self: &Self, token: &Token, username: &String) -> bool {
        let redis_client = &*self.redis_client;
        if let Ok(mut conn) = redis_client.get_async_connection().await {
            let key = format!("token:{}", token);
            conn.set(key, username)
                .await
                .map(|_: String| true)
                .unwrap_or(false)
        } else {
            false
        }
    }

    async fn get_username_by_token(self: &Self, token: &Token) -> Option<String> {
        let redis_client = &*self.redis_client;
        if let Ok(mut conn) = redis_client.get_async_connection().await {
            let key = format!("token:{}", token);
            conn.get(key).await.ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[actix_web::main]
    #[test]
    async fn test_save_and_check() {
        let redis_client = redis::Client::open("redis://localhost:6378").unwrap();
        let sut = RedisTokenRepoImpl { redis_client: Arc::new(redis_client) };

        let token = sut.generate_token().await;
        let username = "username".to_string();
        assert_eq!(None, sut.get_username_by_token(&token).await);
        assert_eq!(true, sut.save_token(&token, &username).await);
        assert_eq!(Some(username), sut.get_username_by_token(&token).await);
    }
}
```

同样的，`PostgresCredentialRepo`实现了`CredentialRepo` `trait`.它持有了一个`sqlx`提供的PostgreSql的连接池的引用。测试的时候，我们同样适用docker来提供PostgreSQL数据库实例。每一次运行测试，我们都会重新创建一个独立的数据库，确保测试的隔离性。

```rust
use super::ports::*;
use sqlx::PgPool;
use async_trait::async_trait;
use sqlx::prelude::PgQueryAs;
use std::sync::Arc;

pub struct PostgresCredentialRepoImpl {
    pub pg_pool: Arc<PgPool>
}

#[async_trait]
impl CredentialRepo for PostgresCredentialRepoImpl {
    async fn save_credential(self: &Self, credential: &Credential) -> bool {
        sqlx::query("insert into credentials (username, password) values ($1, crypt($2, gen_salt('bf')))")
            .bind(&credential.username)
            .bind(&credential.password)
            .execute(&*self.pg_pool)
            .await
            .map(|row| row > 0)
            .unwrap_or(false)
    }

    async fn is_credential_exists(self: &Self, credential: &Credential) -> bool {
        let (found,): (bool,) = sqlx::query_as("select true from credentials where username = $1 and password = crypt($2, password)")
            .bind(&credential.username)
            .bind(&credential.password)
            .fetch_one(&*self.pg_pool)
            .await
            .unwrap_or((false,));
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;
    use std::sync::Arc;

    #[actix_web::main]
    #[test]
    async fn test_save_and_check() {
        let pg_pool = PgPool::builder()
            .build("postgresql://postgres:test@localhost:5431")
            .await
            .expect("Unable to connect to DB");
        sqlx::query("drop database if exists test_credential_repo").execute(&pg_pool).await.unwrap();
        sqlx::query("create database test_credential_repo").execute(&pg_pool).await.unwrap();
        let pg_pool = crate::infrastructure::postgresql::configure_with_db_url("postgresql://postgres:test@localhost:5431/test_credential_repo").await;

        let sut = PostgresCredentialRepoImpl { pg_pool: Arc::new(pg_pool) };

        let credential = Credential { username: "u".to_string(), password: "p".to_string() };

        assert_eq!(false, sut.is_credential_exists(&credential).await);

        assert_eq!(true, sut.save_credential(&credential).await);
        assert_eq!(true, sut.is_credential_exists(&credential).await);
    }
}
```

`RestAuthController`适配器和其他的适配器稍微有一点不同。该适配器向领域内进行交互，而其他适配器则相反，由领域向其他适配器进行交互。这个适配器在`actix-web`和我们的领域之间建立了一个桥梁。该适配器的实现在`auth/rest_auth_controller.rs`中。测试方面，我们使用`actix-web`提供的测试功能。主要测的方面是，我们想知道，对于一个给定的HTTP请求，是否可以触发一个正确的Port.

```rust
use super::ports::*;
use actix_web::{web, Responder};
use actix_web::web::Json;

pub fn configure<T: 'static + AuthService>(service: web::Data<T>, cfg: &mut web::ServiceConfig) {
    cfg.app_data(service);
    cfg.route("/register", web::post().to(register::<T>));
    cfg.route("/login", web::post().to(login::<T>));
    cfg.route("/authenticate", web::post().to(authenticate::<T>));
}

async fn register<T: AuthService>(service: web::Data<T>, body: Json<Credential>) -> impl Responder {
    Json(service.register(&body).await)
}

async fn login<T: AuthService>(service: web::Data<T>, body: Json<Credential>) -> impl Responder {
    Json(service.login(&body).await)
}

async fn authenticate<T: AuthService>(service: web::Data<T>, body: Json<String>) -> impl Responder {
    Json(service.authenticate(&body).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use mockall::predicate::*;

    #[actix_web::main]
    #[test]
    async fn test_authenticate_correct() {
        let mut auth_service = MockAuthService::new();
        auth_service.expect_authenticate()
            .with(eq("test".to_string()))
            .return_const(Some("username".to_string()));
        let auth_service = web::Data::new(auth_service);

        let mut sut = test::init_service(App::new().configure(|cfg| configure(auth_service, cfg))).await;

        let req = test::TestRequest::post()
            .uri("/authenticate")
            .set_json(&"test")
            .to_request();
        let resp = test::call_service(&mut sut, req).await;
        let actual_body: Option<String> = test::read_body_json(resp).await;
        assert_eq!(actual_body, Some("username".to_string()));
    }
	
	// Other tests are omitted for brevity
}
```

## 应用
最后，我们在`main.rs`中整合我们已经定义好的各种组件。在这里，我们初始化了PostgreSQL和Redis的连接，然后创建了在应用中实际要使用的组件，并且整合它们。

```rust
mod auth;
mod infrastructure;

use actix_web::{HttpServer, App, web};
use std::sync::Arc;
use sqlx::PgPool;

#[actix_web::main]
async fn main() {
    if let Err(e) = dotenv::dotenv() {
        print!("Not applying .env : {:?}", e);
    }

    let pg_pool = Arc::new(infrastructure::postgresql::configure().await);
    let redis_client = Arc::new(infrastructure::redis::configure().await);

    let port = std::env::var("PORT").expect("PORT env var must be set");
    let address = format!("0.0.0.0:{}", port);
    println!("Binding server to {} ...", address);
    HttpServer::new(move || App::new().configure(|cfg| configure_features(redis_client.clone(), pg_pool.clone(), cfg)))
        .bind(address)
        .expect("Unable to bind server")
        .run()
        .await
        .expect("Failed to start web server")
}

fn configure_features(redis_client: Arc<redis::Client>, pg_pool: Arc<PgPool>, cfg: &mut web::ServiceConfig) {
    configure_auth(redis_client.clone(), pg_pool.clone(), cfg);
}

fn configure_auth(redis_client: Arc<redis::Client>, pg_pool: Arc<PgPool>, cfg: &mut web::ServiceConfig) {
    use crate::auth::auth_service_impl::AuthServiceImpl;
    use crate::auth::postgres_credential_repo::PostgresCredentialRepoImpl;
    use crate::auth::redis_token_repo::RedisTokenRepoImpl;
    use crate::auth::rest_auth_controller;

    let service = AuthServiceImpl {
        credential_repo: PostgresCredentialRepoImpl {
            pg_pool: pg_pool.clone()
        },
        token_repo: RedisTokenRepoImpl {
            redis_client: redis_client.clone()
        }
    };
    rest_auth_controller::configure(web::Data::new(service), cfg);
}
```

我们将`PostgreSQL`和`Redis`相关内容拆分到了各自独立的文件中，它们有各自的初始化逻辑。这样做，稍微提高了可读性。下边会看到两个`main.rs`中引用的组件。
```rust
// postgresql.rs
use sqlx_pg_migrate::migrate;
use include_dir::{include_dir, Dir};
use sqlx::postgres::PgPool;
use std::env;

static MIGRATIONS: Dir = include_dir!("migrations");

pub async fn configure() -> PgPool {
    let db_url = env::var("DB_URL").expect("DB_URL env var needs to be set");
    configure_with_db_url(&db_url).await
}

pub async fn configure_with_db_url(db_url: &str) -> PgPool {
    migrate(&db_url, &MIGRATIONS).await.expect("Unable to migrate DB");
    PgPool::builder()
        .max_size(5)
        .build(&db_url)
        .await
        .expect("Unable to connect to Postgresql")
}
```

```rust
//redis.rs
pub use redis::Client;

pub async fn configure() -> redis::Client {
    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL env var needs to be set");
    redis::Client::open(redis_url).expect("Unable to connect to Redis")
}
```

我们还可以在Application这个层级进行集成测试。运行实际的应用，然后校验功能是否正确。但这是这篇文章之外的内容了。如果你想要了解更多，[**Rust官方文档**](https://doc.rust-lang.org/rust-by-example/testing/integration_testing.html)是一个好的切入点。


# 结尾
在这篇文章中，我们看到了如何组织一个易于测试的Rust项目。基本的观点就是使用端口适配器模式，用`trait`s来作为端口，然后使用test double来作为组件的依赖。这样我们就可以独立的测试每个组件了。

该文章中涉及到的，完整的源代码，可以在[**GitHub**](https://github.com/eckyputrady/testable-rust-web-project)中访问。
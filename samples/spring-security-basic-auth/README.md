# Description
In some situations, the client does not support OAuth protocols so you need to fall back to basic authentication. This sample uses a implementation of the [BearerTokenResolver](https://docs.spring.io/spring-security/site/docs/5.1.1.RELEASE/api/org/springframework/security/oauth2/server/resource/web/BearerTokenResolver.html). Depending on the configuration, this resolver will
- Support OAuth JWT tokens and
  - either exchange incoming credentials using the OAuth password grant flow
  - or exchange incoming credentials using the OAuth client credential flow

In order to get the basic auth login popup, the response header `WWW-Authenticate` must be changed from `Bearer` to `Basic`. 
This is done by means of the class `BasicAuthenticationEntryPoint` in the Security Configuration.

# Coding
This sample is using the spring-security project. As of version 5 of spring-security, this includes the OAuth resource-server functionality. It enables caching using [`Caffeine`](https://github.com/ben-manes/caffeine) to avoid requesting new tokens from XSUAA for every incoming request.

Follow the deployment steps for [Kyma/Kubernetes](#Deployment-on-Kyma/Kubernetes) or [Cloud Foundry](#Deployment-on-Cloud-Foundry).

 
# Deployment on Kyma/Kubernetes
<details>
<summary>Collapse this to follow the deployment steps</summary>
  
- Build docker image and push to repository
- Configure the deployment.yml
- Deploy the application
- Assign Role Collection to your user
- Access the application

## Build docker image and push to repository
```shell script
mvn spring-boot:build-image -Dspring-boot.build-image.imageName=<repositoryName>/<imageName>
docker push <repositoryName>/<imageName>
```

## Configure the deployment.yml
Replace the placeholders for image repository in deployment.yml with the one created in the previous step.

## Deploy the application
Deploy the application using [kubectl cli](https://kubernetes.io/docs/reference/kubectl/)
```shell script
kubectl apply -f ./k8s/deployment.yml -n <YOUR NAMESPACE>
```

## Cockpit administration tasks: Assign Role Collection to your user
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection `JAVA_SECURITY_SAMPLE_Viewer` to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on sap.help.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).

## Access the application
After deployment, the spring service can be called with basic authentication.
```shell
curl -i --user "<SAP ID Service User>:<SAP ID Service Password>" https://spring-security-basic-auth-api.<K8s DOMAIN>/hello-token
```

You will get a response like:
```
{
  "client id": "sb-spring-security-xsuaa-usage!t291",
  "family name": "Jones",
  "given name": "Bob",
  "subaccount id": "2f047cc0-4364-4d8b-ae70-b8bd39d15bf0",
  "logon name": "bob.jones@example.com",
  "email": "bob.jones@example.com",
  "grant type": "password",
  "authorities": "[openid, spring-security-basic-auth!t19435.Display]",
  "scopes": "[openid, spring-security-basic-auth!t19435.Display]"
}
```

## Cleanup
Finally, delete your application and your service instances using the following commands:
```shell script
 kubectl delete -f ./k8s/deployment.yml
```
</details>

# Deployment on Cloud Foundry
To deploy the application, the following steps are required:
- Compile the Java application
- Create a XSUAA service instance
- Configure the manifest.yml
- Deploy the application
- Assign Role Collection to your user
- Access the application

## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```

## Create the XSUAA service instance
:exclamation: XSUAA supports X.509 authentication method.

- Use the [xs-security.json](./xs-security.json) to define the X.509 authentication method with Xsuaa managed certificate and create a service instance
- Use the [xs-security-deprecated.json](xs-security-deprecated.json) to define the authentication method with binding secret method and settings and create a service instance
```shell
cf create-service xsuaa application xsuaa-basic -c xs-security.json
```

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Cockpit administration tasks: Assign Role to your User
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection such as `BASIC_AUTH_API_Viewer` to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on sap.help.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).


## Access the application
After deployment, the spring service can be called with basic authentication.
```shell
curl -i --user "<SAP ID Service User>:<SAP ID Service Password>" https://spring-security-basic-auth-<ID>.<LANDSCAPE_APPS_DOMAIN>/hello-token
```

You will get a response like:
```
{
  "client id": "sb-spring-security-xsuaa-usage!t291",
  "family name": "Jones",
  "given name": "Bob",
  "subaccount id": "2f047cc0-4364-4d8b-ae70-b8bd39d15bf0",
  "logon name": "bob.jones@example.com",
  "email": "bob.jones@example.com",
  "grant type": "password",
  "authorities": "[openid, spring-security-basic-auth!t19435.Display]",
  "scopes": "[openid, spring-security-basic-auth!t19435.Display]"
}
```

## Clean-Up

Finally delete your application and your service instances using the following commands:
```
cf delete -f spring-security-basic-auth
cf delete-service -f xsuaa-basic
```


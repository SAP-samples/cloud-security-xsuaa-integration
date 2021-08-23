# Description
This sample is a Java back-end application running on SAP Cloud Business Technology Platform. On incoming requests it checks whether the user is authorized using the 
[`XsuaaTokenAuthenticator`](/java-security/src/main/java/com/sap/cloud/security/servlet/XsuaaTokenAuthenticator.java) which is defined in the [Java Security](../../java-security/) library.

Follow the deployment steps for [Kyma/Kubernetes](#Deployment-on-Kyma/Kubernetes) or [Cloud Foundry](#Deployment-on-Cloud-Foundry).


# Deployment on Kyma/Kubernetes
<details>
<summary>Collapse this to follow the deployment steps</summary>

- Compile the Java application
- Build docker image and push to repository
- Configure the deployment.yml
- Deploy the application
- Assign Role Collection to your user
- Access the application

## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```
## Build docker image and push to repository
```shell script
docker build -t <repositoryName>/<imageName> -f ./Dockerfile . 
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
- Get an access token via `curl`. You can get the information to fill the placeholders from the service binding secret:
```shell script
kubectl get secret "xsuaa-service-binding" -o go-template='{{range $k,$v := .data}}{{"### "}}{{$k}}{{"\n"}}{{$v|base64decode}}{{"\n\n"}}{{end}}' -n <YOUR NAMESPACE>
```

```
curl -X POST \
  <<url>>/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=<<clientid>>&client_secret=<<clientsecret>>&grant_type=password&username=<<your username>>&password=<<your password>>'
```

Copy the `access_token` to your clipboard.

- Access the app via `curl`. Don't forget to fill the placeholders.
```
curl -X GET \
  https://java-security-api.<<K8S DOMAIN>>/java-security-usage/hello-java-security \
  -H 'Authorization: Bearer <<your access_token>>'
```

You should see something like this:
```
You ('<your user>') can access the application with the following scopes: '<your scopes>'.
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
- Create a xsuaa service instance
- Configure the manifest
- Deploy the application
- Assign Role Collection to your user
- Access the application

## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```

## Create the xsuaa service instance
Use the [xs-security.json](./xs-security.json) to define the authentication settings and create a service instance
```shell
cf create-service xsuaa application xsuaa-java-security -c xs-security.json
```

## Configure the manifest
The [vars](../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Cockpit administration tasks: Assign Role to your User
Finally, as part of your Identity Provider, e.g. SAP ID Service, assign the deployed Role Collection `JAVA_SECURITY_SAMPLE_Viewer` to your user as depicted in the screenshot below and as documented [here](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/9e1bf57130ef466e8017eab298b40e5e.html).

![](../images/SAP_CP_Cockpit_AssignRoleCollectionToUser.png)

Further up-to-date information you can get on sap.help.com:
- [Maintain Role Collections](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/d5f1612d8230448bb6c02a7d9c8ac0d1.html)
- [Maintain Roles for Applications](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/7596a0bdab4649ac8a6f6721dc72db19.html).


## Access the application
- Get an access token via `curl`. You can get the information to fill the placeholders from your system environment `cf env java-security-usage`:

```
curl -X POST \
  <<VCAP_SERVICES.xsuaa.credentials.url>>/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=<<VCAP_SERVICES.xsuaa.credentials.clientid>>&client_secret=<<VCAP_SERVICES.xsuaa.credentials.clientsecret>>&grant_type=password&username=<<your username>>&password=<<your password>>'
```

Copy the `access_token` to your clipboard.

- Access the app via `curl`. Don't forget to fill the placeholders.
```
curl -X GET \
  https://java-security-usage-<<ID>>.<<LANDSCAPE_APPS_DOMAIN>>/hello-java-security \
  -H 'Authorization: Bearer <<your access_token>>'
```

You should see something like this:
```
You ('<your user>') can access the application with the following scopes: '<your scopes>'.
```

## Clean-Up
Finally, delete your application and your service instances using the following commands:
```
cf delete -f java-security-usage
cf delete-service -f xsuaa-java-security
```

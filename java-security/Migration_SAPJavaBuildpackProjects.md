# Migration Guide for J2EE Web Applications that use SAP Buildpack for securing their applications


**This document is only applicable for J2EE web applications securing their application with SAP Java Buildpack.** The SAP Java Buildpack version `1.26.1` and the SAP Java Buildpack for XSA version `1.8.18` does not any longer provide deprecated SAP-internal security libraries and does not longer depend on Spring security.

This migration document is a step-by-step guide explaining how to replace your dependencies to the deprecated SAP-internal security libraries with the open-sourced [SAP CP Java Security client library](/java-security).

## Prerequisites

Please note, this Migration Guide is only intended for applications using SAP Java Buildpack. You're using the SAP Java Buildpack if you can find the `sap_java_buildpack` in the deployment descriptor of your application, e.g. in your `manifest.yml` file.

## Cleanup Maven Dependencies <a name="maven"></a>

First check the `pom.xml` of your application for dependencies to the deprecated sap-internal security api projects:

groupId (deprecated) | artifactId (deprecated) 
--- | --- 
com.sap.xs2.security | java-container-security-api 
com.sap.cloud.security.xssec | api 
com.sap.cloud.security.xsuaa | java-container-security-api 

**If you do not have any of the api projects above as dependency you can skip this guide!**

The above mentioned dependencies should be removed / replaced with this one:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.sap.cloud.sjb.cf</groupId>
            <artifactId>sap-java-buildpack-bom</artifactId>
            <version>1.31.1</version><!-- set to actual buildpack version -->
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependency>
    <groupId>com.sap.cloud.security.xsuaa</groupId>
    <artifactId>api</artifactId>
</dependency>
```

> :bulb: This manages your SAP Java buildpack dependencies using [Bill of Materials](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/6c6936e8e4ea40c9a9a69f6783b1e978.html). Check [SJB BoM on Maven Repository](https://mvnrepository.com/artifact/com.sap.cloud.sjb.cf/sap-java-buildpack-bom) to see which versions are provided.

Furthermore, make sure that you do not refer to any other SAP-internal security library with group-id `com.sap.security` or `com.sap.security.nw.sso.*`. 


### SAP_JWT_TRUST_ACL obsolete
There is no need to configure `SAP_JWT_TRUST_ACL` within your deployment descriptor such as `manifest.yml`. 
Instead the Xsuaa service instance adds audiences to the issued JSON Web Token (JWT) as part of the `aud` claim.

Whether the token is issued for your application or not is now validated by the [`JwtAudienceValidator`](/java-security/src/main/java/com/sap/cloud/security/token/validation/validators/JwtAudienceValidator.java).

This comes with a change regarding scopes. For a business application A that wants to call an application B, it's now mandatory that the application B grants at least one scope to the calling business application A. You can grant scopes with the `xs-security.json` file. For additional information, refer to the [Application Security Descriptor Configuration Syntax](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/517895a9612241259d6941dbf9ad81cb.html), specifically the sections [referencing the application](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/517895a9612241259d6941dbf9ad81cb.html#loio517895a9612241259d6941dbf9ad81cb__section_fm2_wsk_pdb) and [authorities](https://help.sap.com/viewer/65de2977205c403bbc107264b8eccf4b/Cloud/en-US/517895a9612241259d6941dbf9ad81cb.html#loio517895a9612241259d6941dbf9ad81cb__section_d1m_1nq_zy). 

### Congratulation! With that you're Done!

## Issues
In case you face issues to apply the migration steps check this [troubleshooting](README.md#troubleshooting) for known issues and how to file the issue.

## [OPTIONAL] Leverage new API and features
You can continue [here](Migration_SAPJavaBuildpackProjects_V2.md) to understand what needs to be done to leverage the new `java-api` that is exposed by the SAP Java Buildpack starting with version `1.26.1`.

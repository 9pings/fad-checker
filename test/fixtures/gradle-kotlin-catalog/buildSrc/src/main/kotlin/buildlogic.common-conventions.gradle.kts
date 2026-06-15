plugins {
    java
}

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:${libs.findVersion("spring-boot").get()}"))
}

plugins {
    id("buildlogic.common-conventions")
    id("org.springframework.boot")
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation(libs.clamav.client)
    implementation(libs.commons.codec)

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

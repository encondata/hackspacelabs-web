FROM quay.io/keycloak/keycloak:26.8.2 AS builder
ENV KC_DB=postgres KC_HEALTH_ENABLED=true
RUN /opt/keycloak/bin/kc.sh build
FROM quay.io/keycloak/keycloak:26.8.2
COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY keycloak/hackspacelabs-realm.json /opt/keycloak/data/import/hackspacelabs-realm.json
COPY keycloak/themes/hackspacelabs /opt/keycloak/themes/hackspacelabs
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]

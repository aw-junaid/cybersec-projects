#ifndef REGISTRY_H
#define REGISTRY_H

int fetch_image_manifest(const char* image, char** manifest_json);
int parse_manifest_layers(const char* manifest_json, char*** layers, int* layer_count);

#endif

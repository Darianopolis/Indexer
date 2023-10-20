if Project "index" then
    Compile "src/**"
    Include "src"
    Import {
        "simdutf",
        "ankerl-maps",
        "nova",
    }
    Artifact { "out/main", type = "Console" }
end
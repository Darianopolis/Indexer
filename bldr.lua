if Project "index" then
    Compile "src/**"
    Include "src"
    Import {
        "simdutf",
        "ankerl-maps",
        "nova",
    }
end

if Project "index-test" then
    Import "index"
    Compile "test/main.cpp"
    Artifact { "out/main", type = "Console" }
end
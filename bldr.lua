if Project "fs-indexer" then
    Compile "src/*"
    Include "src"
    Import "nova"
end

if Project "ntfs-index" then
    Compile "src/ntfs3/*"
    Import "ankerl-maps"
    Artifact { "out/index", type = "Console" }
end
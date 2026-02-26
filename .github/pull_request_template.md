## Summary
- 

## Validation
- [ ] `go test -tags debug ./main/ngrok ./main/ngrokd ./client ./server ./conn ./msg ./proto ./util ./cache ./log ./version ./client/views/web`
- [ ] `go test -race -tags debug ./server ./util ./client/views/web` (if concurrency touched)
- [ ] `go vet -tags debug ./main/ngrok ./main/ngrokd ./client ./server ./conn ./msg ./proto ./util ./cache ./log ./version ./client/views/web`

## Changelog
- [ ] Updated `docs/CHANGELOG.md` using `docs/CHANGELOG_TEMPLATE.md`
- [ ] Not required (internal-only/no user-facing changes)




/*
 * SQLite3 configuration.
 */
#ifndef SQLITE_HAS_CODEC
#define SQLITE_HAS_CODEC 1
#endif
#ifndef SQLITE_TEMP_STORE
#define SQLITE_TEMP_STORE 2
#endif

/*
 * sqleet_configuration.
 *
 * # SKIP_HEADER_BYTES
 * Keep this many bytes unencrypted in the beginning of the database header.
 * Use 24 for better compatibility with the SQLite3 Encryption Extension (SEE).
 */
#ifndef SKIP_HEADER_BYTES
#define SKIP_HEADER_BYTES 0
#endif

#include "sqlite3.c"

//----------------------------------------------------------------------
// @@@ rekeyvacuum.c

/*
** Adjusted version of sqlite3RunVacuum to allow reducing or removing reserved page space
** For this purpose the number of reserved bytes per page for the target database is
** passed as a parameter to the adjusted function.
**
** NOTE: When upgrading to a new version of SQLite3 it is strongly recommended to check
** the original function sqlite3RunVacuum of the new version for relevant changes, and
** to incorporate them in the adjusted function below.
**
** The code below is based on SQLite version 3.23.0.
*/

/*
** This routine implements the OP_Vacuum opcode of the VDBE.
*/
/* CHANGE 1 of 3: Add function parameter nRes */
SQLITE_PRIVATE int sqlite3RunVacuumForRekey(char **pzErrMsg, sqlite3 *db, int iDb, int nRes){
  int rc = SQLITE_OK;     /* Return code from service routines */
  Btree *pMain;           /* The database being vacuumed */
  Btree *pTemp;           /* The temporary database we vacuum into */
  u16 saved_mDbFlags;     /* Saved value of db->mDbFlags */
  u32 saved_flags;        /* Saved value of db->flags */
  int saved_nChange;      /* Saved value of db->nChange */
  int saved_nTotalChange; /* Saved value of db->nTotalChange */
  u8 saved_mTrace;        /* Saved trace settings */
  Db *pDb = 0;            /* Database to detach at end of vacuum */
  int isMemDb;            /* True if vacuuming a :memory: database */
  /* CHANGE 2 of 3: Do not define local variable nRes */
  /*int nRes;*/               /* Bytes of reserved space at the end of each page */
  int nDb;                /* Number of attached databases */
  const char *zDbMain;    /* Schema name of database to vacuum */
  
  if( !db->autoCommit ){
    sqlite3SetString(pzErrMsg, db, "cannot VACUUM from within a transaction");
    return SQLITE_ERROR;
  }
  if( db->nVdbeActive>1 ){
    sqlite3SetString(pzErrMsg, db,"cannot VACUUM - SQL statements in progress");
    return SQLITE_ERROR;
  }

  /* Save the current value of the database flags so that it can be 
  ** restored before returning. Then set the writable-schema flag, and
  ** disable CHECK and foreign key constraints.  */
  saved_flags = db->flags;
  saved_mDbFlags = db->mDbFlags;
  saved_nChange = db->nChange;
  saved_nTotalChange = db->nTotalChange;
  saved_mTrace = db->mTrace;
  db->flags |= SQLITE_WriteSchema | SQLITE_IgnoreChecks;
  db->mDbFlags |= DBFLAG_PreferBuiltin | DBFLAG_Vacuum;
  db->flags &= ~(SQLITE_ForeignKeys | SQLITE_ReverseOrder | SQLITE_CountRows);
  db->mTrace = 0;

  zDbMain = db->aDb[iDb].zDbSName;
  pMain = db->aDb[iDb].pBt;
  isMemDb = sqlite3PagerIsMemdb(sqlite3BtreePager(pMain));

  /* Attach the temporary database as 'vacuum_db'. The synchronous pragma
  ** can be set to 'off' for this file, as it is not recovered if a crash
  ** occurs anyway. The integrity of the database is maintained by a
  ** (possibly synchronous) transaction opened on the main database before
  ** sqlite3BtreeCopyFile() is called.
  **
  ** An optimisation would be to use a non-journaled pager.
  ** (Later:) I tried setting "PRAGMA vacuum_db.journal_mode=OFF" but
  ** that actually made the VACUUM run slower.  Very little journalling
  ** actually occurs when doing a vacuum since the vacuum_db is initially
  ** empty.  Only the journal header is written.  Apparently it takes more
  ** time to parse and run the PRAGMA to turn journalling off than it does
  ** to write the journal header file.
  */
  nDb = db->nDb;
  rc = execSql(db, pzErrMsg, "ATTACH''AS vacuum_db");
  if( rc!=SQLITE_OK ) goto end_of_vacuum;
  assert( (db->nDb-1)==nDb );
  pDb = &db->aDb[nDb];
  assert( strcmp(pDb->zDbSName,"vacuum_db")==0 );
  pTemp = pDb->pBt;

  /* The call to execSql() to attach the temp database has left the file
  ** locked (as there was more than one active statement when the transaction
  ** to read the schema was concluded. Unlock it here so that this doesn't
  ** cause problems for the call to BtreeSetPageSize() below.  */
  sqlite3BtreeCommit(pTemp);

  /* CHANGE 3 of 3: Do not call sqlite3BtreeGetOptimalReserve */
  /*nRes = sqlite3BtreeGetOptimalReserve(pMain);*/

  /* A VACUUM cannot change the pagesize of an encrypted database. */
#ifdef SQLITE_HAS_CODEC
  if( db->nextPagesize ){
    extern void sqlite3CodecGetKey(sqlite3*, int, void**, int*);
    int nKey;
    char *zKey;
    sqlite3CodecGetKey(db, iDb, (void**)&zKey, &nKey);
    if( nKey ) db->nextPagesize = 0;
  }
#endif

  sqlite3BtreeSetCacheSize(pTemp, db->aDb[iDb].pSchema->cache_size);
  sqlite3BtreeSetSpillSize(pTemp, sqlite3BtreeSetSpillSize(pMain,0));
  sqlite3BtreeSetPagerFlags(pTemp, PAGER_SYNCHRONOUS_OFF|PAGER_CACHESPILL);

  /* Begin a transaction and take an exclusive lock on the main database
  ** file. This is done before the sqlite3BtreeGetPageSize(pMain) call below,
  ** to ensure that we do not try to change the page-size on a WAL database.
  */
  rc = execSql(db, pzErrMsg, "BEGIN");
  if( rc!=SQLITE_OK ) goto end_of_vacuum;
  rc = sqlite3BtreeBeginTrans(pMain, 2);
  if( rc!=SQLITE_OK ) goto end_of_vacuum;

  /* Do not attempt to change the page size for a WAL database */
  if( sqlite3PagerGetJournalMode(sqlite3BtreePager(pMain))
                                               ==PAGER_JOURNALMODE_WAL ){
    db->nextPagesize = 0;
  }

  if( sqlite3BtreeSetPageSize(pTemp, sqlite3BtreeGetPageSize(pMain), nRes, 0)
   || (!isMemDb && sqlite3BtreeSetPageSize(pTemp, db->nextPagesize, nRes, 0))
   || NEVER(db->mallocFailed)
  ){
    rc = SQLITE_NOMEM_BKPT;
    goto end_of_vacuum;
  }

#ifndef SQLITE_OMIT_AUTOVACUUM
  sqlite3BtreeSetAutoVacuum(pTemp, db->nextAutovac>=0 ? db->nextAutovac :
                                           sqlite3BtreeGetAutoVacuum(pMain));
#endif

  /* Query the schema of the main database. Create a mirror schema
  ** in the temporary database.
  */
  db->init.iDb = nDb; /* force new CREATE statements into vacuum_db */
  rc = execSqlF(db, pzErrMsg,
      "SELECT sql FROM \"%w\".sqlite_master"
      " WHERE type='table'AND name<>'sqlite_sequence'"
      " AND coalesce(rootpage,1)>0",
      zDbMain
  );
  if( rc!=SQLITE_OK ) goto end_of_vacuum;
  rc = execSqlF(db, pzErrMsg,
      "SELECT sql FROM \"%w\".sqlite_master"
      " WHERE type='index' AND length(sql)>10",
      zDbMain
  );
  if( rc!=SQLITE_OK ) goto end_of_vacuum;
  db->init.iDb = 0;

  /* Loop through the tables in the main database. For each, do
  ** an "INSERT INTO vacuum_db.xxx SELECT * FROM main.xxx;" to copy
  ** the contents to the temporary database.
  */
  rc = execSqlF(db, pzErrMsg,
      "SELECT'INSERT INTO vacuum_db.'||quote(name)"
      "||' SELECT*FROM\"%w\".'||quote(name)"
      "FROM vacuum_db.sqlite_master "
      "WHERE type='table'AND coalesce(rootpage,1)>0",
      zDbMain
  );
  assert( (db->mDbFlags & DBFLAG_Vacuum)!=0 );
  db->mDbFlags &= ~DBFLAG_Vacuum;
  if( rc!=SQLITE_OK ) goto end_of_vacuum;

  /* Copy the triggers, views, and virtual tables from the main database
  ** over to the temporary database.  None of these objects has any
  ** associated storage, so all we have to do is copy their entries
  ** from the SQLITE_MASTER table.
  */
  rc = execSqlF(db, pzErrMsg,
      "INSERT INTO vacuum_db.sqlite_master"
      " SELECT*FROM \"%w\".sqlite_master"
      " WHERE type IN('view','trigger')"
      " OR(type='table'AND rootpage=0)",
      zDbMain
  );
  if( rc ) goto end_of_vacuum;

  /* At this point, there is a write transaction open on both the 
  ** vacuum database and the main database. Assuming no error occurs,
  ** both transactions are closed by this block - the main database
  ** transaction by sqlite3BtreeCopyFile() and the other by an explicit
  ** call to sqlite3BtreeCommit().
  */
  {
    u32 meta;
    int i;

    /* This array determines which meta meta values are preserved in the
    ** vacuum.  Even entries are the meta value number and odd entries
    ** are an increment to apply to the meta value after the vacuum.
    ** The increment is used to increase the schema cookie so that other
    ** connections to the same database will know to reread the schema.
    */
    static const unsigned char aCopy[] = {
       BTREE_SCHEMA_VERSION,     1,  /* Add one to the old schema cookie */
       BTREE_DEFAULT_CACHE_SIZE, 0,  /* Preserve the default page cache size */
       BTREE_TEXT_ENCODING,      0,  /* Preserve the text encoding */
       BTREE_USER_VERSION,       0,  /* Preserve the user version */
       BTREE_APPLICATION_ID,     0,  /* Preserve the application id */
    };

    assert( 1==sqlite3BtreeIsInTrans(pTemp) );
    assert( 1==sqlite3BtreeIsInTrans(pMain) );

    /* Copy Btree meta values */
    for(i=0; i<ArraySize(aCopy); i+=2){
      /* GetMeta() and UpdateMeta() cannot fail in this context because
      ** we already have page 1 loaded into cache and marked dirty. */
      sqlite3BtreeGetMeta(pMain, aCopy[i], &meta);
      rc = sqlite3BtreeUpdateMeta(pTemp, aCopy[i], meta+aCopy[i+1]);
      if( NEVER(rc!=SQLITE_OK) ) goto end_of_vacuum;
    }

    rc = sqlite3BtreeCopyFile(pMain, pTemp);
    if( rc!=SQLITE_OK ) goto end_of_vacuum;
    rc = sqlite3BtreeCommit(pTemp);
    if( rc!=SQLITE_OK ) goto end_of_vacuum;
#ifndef SQLITE_OMIT_AUTOVACUUM
    sqlite3BtreeSetAutoVacuum(pMain, sqlite3BtreeGetAutoVacuum(pTemp));
#endif
  }

  assert( rc==SQLITE_OK );
  rc = sqlite3BtreeSetPageSize(pMain, sqlite3BtreeGetPageSize(pTemp), nRes,1);

end_of_vacuum:
  /* Restore the original value of db->flags */
  db->init.iDb = 0;
  db->mDbFlags = saved_mDbFlags;
  db->flags = saved_flags;
  db->nChange = saved_nChange;
  db->nTotalChange = saved_nTotalChange;
  db->mTrace = saved_mTrace;
  sqlite3BtreeSetPageSize(pMain, -1, -1, 1);

  /* Currently there is an SQL level transaction open on the vacuum
  ** database. No locks are held on any other files (since the main file
  ** was committed at the btree level). So it safe to end the transaction
  ** by manually setting the autoCommit flag to true and detaching the
  ** vacuum database. The vacuum_db journal file is deleted when the pager
  ** is closed by the DETACH.
  */
  db->autoCommit = 1;

  if( pDb ){
    sqlite3BtreeClose(pDb->pBt);
    pDb->pBt = 0;
    pDb->pSchema = 0;
  }

  /* This both clears the schemas and reduces the size of the db->aDb[]
  ** array. */ 
  sqlite3ResetAllSchemasOfConnection(db);

  return rc;
}



// @@@ end of rekeyvacuum.c 
//----------------------------------------------------------------------
// @@@ crypto.c 

/* This file is included by sqleet.c */
#include <stdint.h>

#define ROL32(x, c) (((x) << (c)) | ((x) >> (32-(c))))
#define ROR32(x, c) (((x) >> (c)) | ((x) << (32-(c))))

#define LOAD32_LE(p)                \
    ( ((uint32_t)((p)[0]) <<  0)    \
    | ((uint32_t)((p)[1]) <<  8)    \
    | ((uint32_t)((p)[2]) << 16)    \
    | ((uint32_t)((p)[3]) << 24)    \
    )
#define LOAD32_BE(p)                \
    ( ((uint32_t)((p)[3]) <<  0)    \
    | ((uint32_t)((p)[2]) <<  8)    \
    | ((uint32_t)((p)[1]) << 16)    \
    | ((uint32_t)((p)[0]) << 24)    \
    )

#define STORE32_LE(p, v)            \
    (p)[0] = ((v) >>  0) & 0xFF;    \
    (p)[1] = ((v) >>  8) & 0xFF;    \
    (p)[2] = ((v) >> 16) & 0xFF;    \
    (p)[3] = ((v) >> 24) & 0xFF;
#define STORE32_BE(p, v)            \
    (p)[3] = ((v) >>  0) & 0xFF;    \
    (p)[2] = ((v) >>  8) & 0xFF;    \
    (p)[1] = ((v) >> 16) & 0xFF;    \
    (p)[0] = ((v) >> 24) & 0xFF;
#define STORE64_BE(p, v)            \
    (p)[7] = ((v) >>  0) & 0xFF;    \
    (p)[6] = ((v) >>  8) & 0xFF;    \
    (p)[5] = ((v) >> 16) & 0xFF;    \
    (p)[4] = ((v) >> 24) & 0xFF;    \
    (p)[3] = ((v) >> 32) & 0xFF;    \
    (p)[2] = ((v) >> 40) & 0xFF;    \
    (p)[1] = ((v) >> 48) & 0xFF;    \
    (p)[0] = ((v) >> 56) & 0xFF;

/*
 * ChaCha20 stream cipher
 */
static void chacha20_block(unsigned char out[64], const uint32_t in[16])
{
    int i;
    uint32_t x[16];
    memcpy(x, in, sizeof(uint32_t) * 16);

    #define QR(x, a, b, c, d)                           \
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROL32(x[d], 16); \
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROL32(x[b], 12); \
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROL32(x[d],  8); \
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROL32(x[b],  7);
    for (i = 0; i < 10; i++) {
        /* Column round */
        QR(x, 0, 4, 8, 12)
        QR(x, 1, 5, 9, 13)
        QR(x, 2, 6, 10, 14)
        QR(x, 3, 7, 11, 15)
        /* Diagonal round */
        QR(x, 0, 5, 10, 15)
        QR(x, 1, 6, 11, 12)
        QR(x, 2, 7, 8, 13)
        QR(x, 3, 4, 9, 14)
    }
    #undef QR
    for (i = 0; i < 16; i++) {
        const uint32_t v = x[i] + in[i];
        STORE32_LE(out, v);
        out += 4;
    }
}

void chacha20_xor(unsigned char *data, size_t n, const unsigned char key[32],
                  const unsigned char nonce[12], uint32_t counter)
{
    int i;
    uint32_t state[16];
    unsigned char block[64];
    static const unsigned char sigma[16] = "expand 32-byte k";

    state[ 0] = LOAD32_LE(sigma +  0);
    state[ 1] = LOAD32_LE(sigma +  4);
    state[ 2] = LOAD32_LE(sigma +  8);
    state[ 3] = LOAD32_LE(sigma + 12);

    state[ 4] = LOAD32_LE(key +  0);
    state[ 5] = LOAD32_LE(key +  4);
    state[ 6] = LOAD32_LE(key +  8);
    state[ 7] = LOAD32_LE(key + 12);
    state[ 8] = LOAD32_LE(key + 16);
    state[ 9] = LOAD32_LE(key + 20);
    state[10] = LOAD32_LE(key + 24);
    state[11] = LOAD32_LE(key + 28);

    state[12] = counter;

    state[13] = LOAD32_LE(nonce + 0);
    state[14] = LOAD32_LE(nonce + 4);
    state[15] = LOAD32_LE(nonce + 8);

    while (n >= 64) {
        chacha20_block(block, state);
        for (i = 0; i < 64; i++) {
            data[i] ^= block[i];
        }
        state[12]++;
        data += 64;
        n -= 64;
    }

    if (n > 0) {
        chacha20_block(block, state);
        for (i = 0; i < n; i++) {
            data[i] ^= block[i];
        }
    }
    return;
}

/*
 * Poly1305 authentication tags
 */
void poly1305(const unsigned char *msg, size_t n, const unsigned char key[32],
              unsigned char tag[16])
{
    uint32_t c, m, w;
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint64_t f0, f1, f2, f3;
    uint32_t g0, g1, g2, g3, g4;
    uint32_t h0, h1, h2, h3, h4;
    unsigned char buf[16];
    int i;

    c = 1 << 24;
    r0 = (LOAD32_LE(key +  0) >> 0) & 0x03FFFFFF;
    r1 = (LOAD32_LE(key +  3) >> 2) & 0x03FFFF03;
    r2 = (LOAD32_LE(key +  6) >> 4) & 0x03FFC0FF;
    r3 = (LOAD32_LE(key +  9) >> 6) & 0x03F03FFF;
    r4 = (LOAD32_LE(key + 12) >> 8) & 0x000FFFFF;
    s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;
    h0 = h1 = h2 = h3 = h4 = 0;
    while (n >= 16) {
        uint64_t d0, d1, d2, d3, d4;
process_block:
        h0 += (LOAD32_LE(msg +  0) >> 0) & 0x03FFFFFF;
        h1 += (LOAD32_LE(msg +  3) >> 2) & 0x03FFFFFF;
        h2 += (LOAD32_LE(msg +  6) >> 4) & 0x03FFFFFF;
        h3 += (LOAD32_LE(msg +  9) >> 6) & 0x03FFFFFF;
        h4 += (LOAD32_LE(msg + 12) >> 8) | c;

        #define MUL(a,b) ((uint64_t)(a) * (b))
        d0 = MUL(h0,r0) + MUL(h1,s4) + MUL(h2,s3) + MUL(h3,s2) + MUL(h4,s1);
        d1 = MUL(h0,r1) + MUL(h1,r0) + MUL(h2,s4) + MUL(h3,s3) + MUL(h4,s2);
        d2 = MUL(h0,r2) + MUL(h1,r1) + MUL(h2,r0) + MUL(h3,s4) + MUL(h4,s3);
        d3 = MUL(h0,r3) + MUL(h1,r2) + MUL(h2,r1) + MUL(h3,r0) + MUL(h4,s4);
        d4 = MUL(h0,r4) + MUL(h1,r3) + MUL(h2,r2) + MUL(h3,r1) + MUL(h4,r0);
        #undef MUL

        h0 = d0 & 0x03FFFFFF; d1 += (uint32_t)(d0 >> 26);
        h1 = d1 & 0x03FFFFFF; d2 += (uint32_t)(d1 >> 26);
        h2 = d2 & 0x03FFFFFF; d3 += (uint32_t)(d2 >> 26);
        h3 = d3 & 0x03FFFFFF; d4 += (uint32_t)(d3 >> 26);
        h4 = d4 & 0x03FFFFFF; h0 += (uint32_t)(d4 >> 26) * 5;
        h1 += (h0 >> 26); h0 = h0 & 0x03FFFFFF;

        msg += 16;
        n -= 16;
    }
    if (n) {
        for (i = 0; i < n; i++) buf[i] = msg[i];
        buf[i++] = 1;
        while (i < 16) buf[i++] = 0;
        msg = buf;
        n = 16;
        c = 0;
        goto process_block;
    }
    *(volatile uint32_t *)&r0 = 0;
    *(volatile uint32_t *)&r1 = 0; *(volatile uint32_t *)&s1 = 0;
    *(volatile uint32_t *)&r2 = 0; *(volatile uint32_t *)&s2 = 0;
    *(volatile uint32_t *)&r3 = 0; *(volatile uint32_t *)&s3 = 0;
    *(volatile uint32_t *)&r4 = 0; *(volatile uint32_t *)&s4 = 0;

    h2 += (h1 >> 26); h1 &= 0x03FFFFFF;
    h3 += (h2 >> 26); h2 &= 0x03FFFFFF;
    h4 += (h3 >> 26); h3 &= 0x03FFFFFF;
    h0 += (h4 >> 26) * 5; h4 &= 0x03FFFFFF;
    h1 += (h0 >> 26); h0 &= 0x03FFFFFF;

    g0 = h0 + 5;
    g1 = h1 + (g0 >> 26); g0 &= 0x03FFFFFF;
    g2 = h2 + (g1 >> 26); g1 &= 0x03FFFFFF;
    g3 = h3 + (g2 >> 26); g2 &= 0x03FFFFFF;
    g4 = h4 + (g3 >> 26) - (1 << 26); g3 &= 0x03FFFFFF;

    w = ~(m = (g4 >> 31) - 1);
    h0 = (h0 & w) | (g0 & m);
    h1 = (h1 & w) | (g1 & m);
    h2 = (h2 & w) | (g2 & m);
    h3 = (h3 & w) | (g3 & m);
    h4 = (h4 & w) | (g4 & m);

    f0 = ((h0 >>  0) | (h1 << 26)) + (uint64_t)LOAD32_LE(&key[16]);
    f1 = ((h1 >>  6) | (h2 << 20)) + (uint64_t)LOAD32_LE(&key[20]);
    f2 = ((h2 >> 12) | (h3 << 14)) + (uint64_t)LOAD32_LE(&key[24]);
    f3 = ((h3 >> 18) | (h4 <<  8)) + (uint64_t)LOAD32_LE(&key[28]);

    STORE32_LE(tag +  0, f0); f1 += (f0 >> 32);
    STORE32_LE(tag +  4, f1); f2 += (f1 >> 32);
    STORE32_LE(tag +  8, f2); f3 += (f2 >> 32);
    STORE32_LE(tag + 12, f3);
}

int poly1305_tagcmp(const unsigned char tag1[16], const unsigned char tag2[16])
{
    unsigned int d = 0;
    d |= tag1[ 0] ^ tag2[ 0];
    d |= tag1[ 1] ^ tag2[ 1];
    d |= tag1[ 2] ^ tag2[ 2];
    d |= tag1[ 3] ^ tag2[ 3];
    d |= tag1[ 4] ^ tag2[ 4];
    d |= tag1[ 5] ^ tag2[ 5];
    d |= tag1[ 6] ^ tag2[ 6];
    d |= tag1[ 7] ^ tag2[ 7];
    d |= tag1[ 8] ^ tag2[ 8];
    d |= tag1[ 9] ^ tag2[ 9];
    d |= tag1[10] ^ tag2[10];
    d |= tag1[11] ^ tag2[11];
    d |= tag1[12] ^ tag2[12];
    d |= tag1[13] ^ tag2[13];
    d |= tag1[14] ^ tag2[14];
    d |= tag1[15] ^ tag2[15];
    return d;
}

/*
 * SHA256 hash function
 */
struct sha256 {
    uint32_t state[8];
    unsigned char buffer[64];
    uint64_t n64;
    int n;
};

void sha256_init(struct sha256 *ctx)
{
    ctx->state[0] = 0x6a09e667; /* sqrt(2) */
    ctx->state[1] = 0xbb67ae85; /* sqrt(3) */
    ctx->state[2] = 0x3c6ef372; /* sqrt(5) */
    ctx->state[3] = 0xa54ff53a; /* sqrt(7) */
    ctx->state[4] = 0x510e527f; /* sqrt(11) */
    ctx->state[5] = 0x9b05688c; /* sqrt(13) */
    ctx->state[6] = 0x1f83d9ab; /* sqrt(17) */
    ctx->state[7] = 0x5be0cd19; /* sqrt(19) */
    ctx->n64 = 0;
    ctx->n = 0;
}

static void sha256_block(uint32_t state[8], const unsigned char p[64])
{
    uint32_t w[64], a, b, c, d, e, f, g, h;
    uint32_t s0, s1, S0, S1, t1, t2;
    static const uint32_t K256[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7]; 

    #define ROUND_CORE(i)                                           \
    S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);                 \
    t1 = h + S1 + ((e & f) ^ (~e & g)) + K256[i] + w[i];            \
    S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);                 \
    t2 = S0 + ((a & b) ^ (a & c) ^ (b & c));                        \
    h = g; g = f; f = e; e = d + t1;                                \
    d = c; c = b; b = a; a = t1 + t2;

    #define ROUND_0_15(i) w[i] = LOAD32_BE(p); p += 4; ROUND_CORE(i)
    ROUND_0_15( 0) ROUND_0_15( 1) ROUND_0_15( 2) ROUND_0_15( 3)
    ROUND_0_15( 4) ROUND_0_15( 5) ROUND_0_15( 6) ROUND_0_15( 7)
    ROUND_0_15( 8) ROUND_0_15( 9) ROUND_0_15(10) ROUND_0_15(11)
    ROUND_0_15(12) ROUND_0_15(13) ROUND_0_15(14) ROUND_0_15(15)
    #undef ROUND_0_15

    #define ROUND_16_19(i)                                          \
    s0 = ROR32(w[i-15], 7) ^ ROR32(w[i-15], 18) ^ (w[i-15] >> 3);   \
    s1 = ROR32(w[i-2], 17) ^ ROR32(w[i-2],  19) ^ (w[i-2] >> 10);   \
    w[i] = w[i-16] + s0 + w[i-7] + s1; ROUND_CORE(i)
    ROUND_16_19(16) ROUND_16_19(17) ROUND_16_19(18) ROUND_16_19(19)
    ROUND_16_19(20) ROUND_16_19(21) ROUND_16_19(22) ROUND_16_19(23)
    ROUND_16_19(24) ROUND_16_19(25) ROUND_16_19(26) ROUND_16_19(27)
    ROUND_16_19(28) ROUND_16_19(29) ROUND_16_19(30) ROUND_16_19(31)
    ROUND_16_19(32) ROUND_16_19(33) ROUND_16_19(34) ROUND_16_19(35)
    ROUND_16_19(36) ROUND_16_19(37) ROUND_16_19(38) ROUND_16_19(39)
    ROUND_16_19(40) ROUND_16_19(41) ROUND_16_19(42) ROUND_16_19(43)
    ROUND_16_19(44) ROUND_16_19(45) ROUND_16_19(46) ROUND_16_19(47)
    ROUND_16_19(48) ROUND_16_19(49) ROUND_16_19(50) ROUND_16_19(51)
    ROUND_16_19(52) ROUND_16_19(53) ROUND_16_19(54) ROUND_16_19(55)
    ROUND_16_19(56) ROUND_16_19(57) ROUND_16_19(58) ROUND_16_19(59)
    ROUND_16_19(60) ROUND_16_19(61) ROUND_16_19(62) ROUND_16_19(63)
    #undef ROUND_16_19
    #undef ROUND_CORE

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_update(struct sha256 *ctx, const unsigned char *data, size_t n)
{
    if (n < 64 || ctx->n) {
        int i, j = (ctx->n + n < 64) ? n : 64 - ctx->n;
        for (i = 0; i < j; i++) {
            ctx->buffer[ctx->n + i] = data[i];
        }
        if ((ctx->n += j) < 64)
            return;
        sha256_block(ctx->state, ctx->buffer);
        ctx->n64 += 64;
        ctx->n = 0;
        data += j;
        n -= j;
    }

    while (n >= 64) {
        sha256_block(ctx->state, data);
        ctx->n64 += 64;
        data += 64;
        n -= 64;
    }

    if (n) {
        int i = 0;
        while (i < n) {
            ctx->buffer[i] = data[i];
            i++;
        }
        ctx->n = n;
    }
}

static void sha256_serialize(const uint32_t state[8], unsigned char hash[32])
{
    STORE32_BE(hash +  0, state[0]);
    STORE32_BE(hash +  4, state[1]);
    STORE32_BE(hash +  8, state[2]);
    STORE32_BE(hash + 12, state[3]);
    STORE32_BE(hash + 16, state[4]);
    STORE32_BE(hash + 20, state[5]);
    STORE32_BE(hash + 24, state[6]);
    STORE32_BE(hash + 28, state[7]);
}

void sha256_final(struct sha256 *ctx, unsigned char hash[32])
{
    int i;
    unsigned char buf[128];
    uint64_t nbits = (ctx->n64 + ctx->n) * 8;
    buf[0] = 0x80;
    for (i = 1; (ctx->n + i + 8) % 64; buf[i++] = 0);
    STORE64_BE(buf+i, nbits);
    sha256_update(ctx, buf, i+8);
    sha256_serialize(ctx->state, hash);
}

/*
 * PBKDF2-HMAC-SHA256 key derivation optimized to reuse intermediate SHA256
 * states computed in the HMAC-SHA256 calculation of the inner and outer pad.
 */
void pbkdf2_hmac_sha256(const void *pass, size_t m, const void *salt, size_t n,
                        int iter, unsigned char *dk, int dklen)
{
    unsigned char keyblock[64], iblock[64], oblock[64];
    struct sha256 ctx, ictx, octx;
    uint32_t I[8], O[8];
    int i, j, k, len;

    /* Initialize keyblock */
    if (m > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, pass, m);
        sha256_final(&ctx, keyblock);
        memset(keyblock+32, 0, 32);
    } else {
        memcpy(keyblock, pass, m);
        memset(keyblock+m, 0, 64 - m);
    }

    /* Prepare iblock and oblock */
    sha256_init(&ictx);
    sha256_init(&octx);
    for (i = 0; i < 64; i++) {
        iblock[i] = 0x36 ^ keyblock[i];
        oblock[i] = 0x5C ^ keyblock[i];
        *(volatile unsigned char *)(keyblock + i) = 0;
    }
    sha256_update(&ictx, iblock, 64);
    sha256_update(&octx, oblock, 64);
    memset(iblock+32, 0, 32);
    memset(oblock+32, 0, 32);
    STORE32_BE(&iblock[64-4], 96*8);
    STORE32_BE(&oblock[64-4], 96*8);
    iblock[32] = oblock[32] = 0x80;

    /* PBKDF2 main loop */
    for (i = 1; dklen; i++) {
        unsigned char ibuf[4];
        STORE32_BE(ibuf, i);
        memcpy(&ctx, &ictx, sizeof(struct sha256));
        sha256_update(&ctx, salt, n);
        sha256_update(&ctx, ibuf, 4);
        sha256_final(&ctx, oblock);

        memcpy(O, octx.state, 32);
        sha256_block(O, oblock);
        sha256_serialize(O, iblock);

        len = (dklen < 32) ? dklen : 32;
        memcpy(dk, iblock, len);
        for (j = 1; j < iter; j++) {
            memcpy(I, ictx.state, 32);
            memcpy(O, octx.state, 32);
            sha256_block(I, iblock);
            sha256_serialize(I, oblock);
            sha256_block(O, oblock);
            sha256_serialize(O, iblock);
            for (k = 0; k < len; k++) {
                dk[k] ^= iblock[k];
            }
        }
        dklen -= len;
        dk += len;
    }

    /* Burn key material */    /* TODO: is this really necessary? */
    for (i = 0; i < 64; i++) { /* for truly paranoid people, yes */
        *(volatile unsigned char *)(iblock + i) = 0;
        *(volatile unsigned char *)(oblock + i) = 0;
    }
}

/*
 * Platform-specific entropy functions for seeding RNG
 */
#if defined(__unix__) || defined(__APPLE__)
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

#ifdef __linux__
#include <stropts.h>
#include <linux/random.h>
#endif

/* Returns the number of urandom bytes read (either 0 or n) */
static size_t read_urandom(void *buf, size_t n)
{
    size_t i;
    ssize_t ret;
    int fd, count;
    struct stat st;
    int errnold = errno;

    do {
        fd = open("/dev/urandom", O_RDONLY, 0);
    } while (fd == -1 && errno == EINTR);
    if (fd == -1)
        goto fail;
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

    /* Check the sanity of the device node */
    if (fstat(fd, &st) == -1 || !S_ISCHR(st.st_mode)
            #ifdef __linux__
            || ioctl(fd, RNDGETENTCNT, &count) == -1
            #endif
            ) {
        close(fd);
        goto fail;
    }

    /* Read bytes */
    for (i = 0; i < n; i += ret) {
        while ((ret = read(fd, (char *)buf + i, n - i)) == -1) {
            if (errno != EAGAIN && errno != EINTR) {
                close(fd);
                goto fail;
            }
        }
    }
    close(fd);

    /* Verify that the random device returned non-zero data */
    for (i = 0; i < n; i++) {
        if (((unsigned char *)buf)[i] != 0) {
            errno = errnold;
            return n;
        }
    }

    /* Tiny n may unintentionally fall through! */

fail:
    fprintf(stderr, "bad /dev/urandom RNG)\n");
    abort(); /* PANIC! */
    return 0;
}

static size_t entropy(void *buf, size_t n)
{
    #if defined(__linux__) && defined(SYS_getrandom)
    if (syscall(SYS_getrandom, buf, n, 0) == n)
        return n;
    #elif defined(SYS_getentropy)
    if (syscall(SYS_getentropy, buf, n) == 0)
        return n;
    #endif
    return read_urandom(buf, n);
}

#elif defined(_WIN32)

#include <windows.h>
#define RtlGenRandom SystemFunction036
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#pragma comment(lib, "advapi32.lib")

static size_t entropy(void *buf, size_t n)
{
    return RtlGenRandom(buf, n) ? n : 0;
}

#else
#error "Secure pseudorandom number generator unimplemented for this OS"
#endif

/*
 * ChaCha20 random number generator
 */
void chacha20_rng(void *out, size_t n)
{
    static size_t available = 0;
    static uint32_t counter = 0xFFFFFFFF;
    static unsigned char key[32], nonce[12], buffer[64];
    sqlite3_mutex *mutex;
    size_t m;
    
    mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_PRNG);
    sqlite3_mutex_enter(mutex);
    while (n > 0) {
        if (available == 0) {
            if (counter == 0xFFFFFFFF) {
                if (entropy(key, sizeof(key)) != sizeof(key))
                    abort();
                if (entropy(nonce, sizeof(nonce)) != sizeof(nonce))
                    abort();
                counter = 0;
            }
            chacha20_xor(buffer, sizeof(buffer), key, nonce, ++counter);
            available = sizeof(buffer);
        }
        m = (available < n) ? available : n;
        memcpy(out, buffer + (sizeof(buffer) - available), m);
        out = (unsigned char *)out + m;
        available -= m;
        n -= m;
    }
    sqlite3_mutex_leave(mutex);
}


// @@@ end of crypto.c 
//----------------------------------------------------------------------
//----------------------------------------------------------------------


/*
 * SQLite3 codec implementation.
 */
typedef struct codec { 
    struct codec *reader, *writer;
    unsigned char key[32], salt[16];
    void *pagebuf;
    int pagesize;
    const void *zKey;
    int nKey;
} Codec;

Codec *codec_new(const char *zKey, int nKey)
{
    Codec *codec;
    if ((codec = sqlite3_malloc(sizeof(Codec)))) {
        codec->reader = codec->writer = codec;
        memset(codec->key, 0, sizeof(codec->key));
        memset(codec->salt, 0, sizeof(codec->salt));
        codec->pagebuf = NULL;
        codec->pagesize = 0;
        codec->zKey = zKey;
        codec->nKey = nKey;
    }
    return codec;
}

Codec *codec_dup(Codec *src)
{
    Codec *codec;
    if ((codec = codec_new(src->zKey, src->nKey))) {
        codec->reader = (src->reader == src) ? codec : src->reader;
        codec->writer = (src->writer == src) ? codec : src->writer;
        memcpy(codec->salt, src->salt, 16);
        memcpy(codec->key, src->key, 32);
    }
    return codec;
}

void codec_kdf(Codec *codec)
{
    pbkdf2_hmac_sha256(codec->zKey, codec->nKey, codec->salt, 16, 12345,
                       codec->key, 32);

    while (codec->nKey) ((volatile char *)codec->zKey)[--codec->nKey] = '\0';
    codec->zKey = NULL;
}

void codec_free(void *pcodec)
{
    if (pcodec) {
        int i;
        volatile char *p;
        Codec *codec = pcodec;
        if (codec->zKey) {
            p = (void *)codec->zKey;
            for (i = 0; i < codec->nKey; p[i++] = '\0');
            /* zKey memory is allocated by the user */
        }
        if (codec->pagebuf) {
            p = codec->pagebuf;
            for (i = 0; i < codec->pagesize; p[i++] = '\0');
            sqlite3_free(codec->pagebuf);
        }
        p = pcodec;
        for (i = 0; i < sizeof(Codec); p[i++] = '\0');
        sqlite3_free(codec);
    }
}

/*
 * The encrypted database page format.
 *
 * +----------------------------------------+----------------+----------------+
 * | Encrypted data                         | 16-byte nonce  | 16-byte tag    |
 * +----------------------------------------+----------------+----------------+
 *
 * As the only exception, the first page (page_no=1) starts with a plaintext
 * salt contained in the first 16 bytes of the database file. The "master" key
 * is derived from a user-given password with the salt and 12345 iterations of
 * PBKDF-HMAC-SHA256. Future plans include switching to BLAKE2 and Argon2.
 *
 * - The data is encrypted by XORing with the ChaCha20 keystream produced from
 *   the 16-byte nonce and a 32-byte encryption key derived from the master key.
 *   - OK, I lied a little: ChaCha20 uses only the first 12 bytes as the nonce.
 *     However, ChaCha20 also requires an initial value for a counter of 4 bytes
 *     that encodes a block position in the output stream. We derive the counter
 *     value from the last 4 bytes, effectively extending the nonce to 16 bytes.
 *   - Specifically, counter = LOAD32_LE(nonce[12..15])^page_no is first applied
 *     to generate a single 64-byte block from nonce[0..11] and the master key.
 *     The block consists of two 32-byte one-time keys, the former is a Poly1305
 *     key for the authentication tag, and the latter is a ChaCha20 key for the
 *     data encryption. The encryption with the one-time key uses nonce[0..11]
 *     and the initial counter value of counter+1.
 *   - The XOR with page_no prevents malicious reordering of the pages.
 *
 * - The nonce consists of 128 randomly generated bits, which should be enough
 *   to guarantee uniqueness with a reasonable pseudorandom number generator.
 *   - Given a perfect RNG, the adversary needs to observe at least 2^61 nonces
 *     to break Poly1305 with the birthday attack at a success rate of 1%.
 *   - If a nonce is reused, we lose confidentiality of the associated messages.
 *     Moreover, the compromised nonce can also be used to forge valid tags for
 *     new messages having the same nonce (basically, the one-time Poly1305 key
 *     can be recovered from distinct messages with identical nonces).
 *
 * - The tag is a Poly1305 MAC calculated over the encrypted data and the nonce
 *   with the one-time key generated from the master key and the nonce.
 */

#define PAGE_NONCE_LEN 16
#define PAGE_TAG_LEN 16
#define PAGE_RESERVED_LEN (PAGE_NONCE_LEN + PAGE_TAG_LEN)

void *codec_handle(void *codec, void *pdata, Pgno page, int mode)
{
    uint32_t counter;
    unsigned char otk[64], tag[16], *data = pdata;
    Codec *reader = ((Codec *)codec)->reader;
    Codec *writer = ((Codec *)codec)->writer;
    const int skip = (page == 1) ? SKIP_HEADER_BYTES : 0;

    switch (mode) {
    case 0: /* Journal decryption */
    case 2: /* Reload a page */
    case 3: /* Load a page */
        if (reader) {
            int n = reader->pagesize - PAGE_RESERVED_LEN;
            if (page == 1 && reader->zKey) {
                memcpy(reader->salt, data, 16);
                codec_kdf(reader);
            }

            /* Generate one-time keys */
            memset(otk, 0, 64);
            counter = LOAD32_LE(data + n + PAGE_NONCE_LEN-4) ^ page;
            chacha20_xor(otk, 64, reader->key, data + n, counter);

            /* Verify the MAC */
            poly1305(data, n + PAGE_NONCE_LEN, otk, tag);
            if (poly1305_tagcmp(data + n + PAGE_NONCE_LEN, tag) != 0)
                return NULL;

            /* Decrypt */
            chacha20_xor(data + skip, n - skip, otk+32, data + n, counter+1);
            if (page == 1) memcpy(data, "SQLite format 3", 16);
        }
        break;

    case 7: /* Encrypt a journal page (with the reader key) */
        writer = reader;
        /* fall-through */
    case 6: /* Encrypt a main database page */
        if (writer) {
            int n = writer->pagesize - PAGE_RESERVED_LEN;
            data = memcpy(writer->pagebuf, data, writer->pagesize);

            /* Generate one-time keys */
            memset(otk, 0, 64);
            chacha20_rng(data + n, 16);
            counter = LOAD32_LE(data + n + PAGE_NONCE_LEN-4) ^ page;
            chacha20_xor(otk, 64, writer->key, data + n, counter);

            /* Encrypt and authenticate */
            chacha20_xor(data + skip, n - skip, otk+32, data + n, counter+1);
            if (page == 1) memcpy(data, writer->salt, 16);
            poly1305(data, n + PAGE_NONCE_LEN, otk, data + n + PAGE_NONCE_LEN);
        }
        break;
    }

    return data;
}

/* Reads page1 to trigger codec_kdf and verify the encryption key */
static int codec_verify_page1(Codec *codec, Btree *pBt)
{
    int count, rc = SQLITE_OK;
	
    Pager *pager = sqlite3BtreePager(pBt);
    sqlite3PagerSharedLock(pager);
    sqlite3PagerPagecount(pager, &count);
    if (count > 0) {
        DbPage *page;
        rc = SQLITE_NOTADB;
        sqlite3PcacheTruncate(pager->pPCache, 0);
        if (sqlite3PagerGet(pager, 1, &page, 0) == SQLITE_OK) {
            if (!memcmp(page->pData, "SQLite format 3", 16))
                rc = SQLITE_OK;
            sqlite3PagerUnref(page);
        } else {
            sqlite3PagerSetCodec(pager, NULL, NULL, NULL, NULL);
        }
    } else if (codec && codec->zKey) {
        /* Generate a salt and derive an encryption key for an empty database */
        chacha20_rng(codec->salt, 16);
        codec_kdf(codec);
    }
    pager_unlock(pager);
    return rc;
}

/*
 * Set (or unset) a codec for the pager of the specified Btree.
 *
 * The caller must hold the database mutex when calling this function.
 * Note that the function consumes the passed-in codec structure.
 */
static int codec_set_to(Codec *codec, Btree *pBt)
{
    int pagesize;
    Pager *pager = sqlite3BtreePager(pBt);

    if (!codec) {
        /* Unset a codec */
        sqlite3PagerSetCodec(pager, NULL, NULL, NULL, NULL);
        return SQLITE_OK;
    }

    /* Allocate page buffer */
    pagesize = sqlite3BtreeGetPageSize(pBt);
    if (!codec->pagebuf || codec->pagesize != pagesize) {
        void *new = sqlite3_malloc(pagesize);
        if (!new) {
            codec_free(codec);
            return SQLITE_NOMEM;
        }
        if (codec->pagebuf) {
            int i = 0;
            while (i < codec->pagesize)
                ((volatile char *)codec->pagebuf)[i++] = '\0';
            sqlite3_free(codec->pagebuf);
        }
        codec->pagebuf = new;
        codec->pagesize = pagesize;
    }

    /* Force secure delete */
    sqlite3BtreeSecureDelete(pBt, 1);

    /* Adjust the page size and the reserved area */
    if (pager->nReserve != PAGE_RESERVED_LEN) {
        pBt->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED;
        sqlite3BtreeSetPageSize(pBt, pagesize, PAGE_RESERVED_LEN, 0);
    }

    /* Set pager codec and try to read page1 */
    sqlite3PagerSetCodec(pager, codec_handle, NULL, codec_free, codec);
    return codec_verify_page1(codec, pBt);
}

void sqlite3CodecGetKey(sqlite3 *db, int nDb, void **zKey, int *nKey)
{
    /*
     * sqlite3.c calls this function to decide if a database attached without a
     * password should use the encryption scheme of the main database. Returns
     * *nKey == 1 to indicate that the main database encryption is available.
     */
    *zKey = NULL;
    *nKey = !!sqlite3PagerGetCodec(sqlite3BtreePager(db->aDb[nDb].pBt));
}

int sqlite3CodecAttach(sqlite3 *db, int nDb, const void *zKey, int nKey)
{
    int rc;
    Codec *codec;
    Btree *pBt = db->aDb[nDb].pBt;

    rc = SQLITE_NOMEM;
    sqlite3_mutex_enter(db->mutex);
    if (!nKey) {
        /* Attach with an empty key (no encryption) */
        codec_set_to(NULL, pBt);
        rc = codec_verify_page1(NULL, pBt);
    } else if (zKey) {
        /* Attach with the provided key */
        if ((codec = codec_new(zKey, nKey))) {
            rc = codec_set_to(codec, pBt); 
	}
    } else if (nDb != 0) {
        /* Use the main database's encryption */
        codec = sqlite3PagerGetCodec(sqlite3BtreePager(db->aDb[0].pBt));
        if (codec && (codec = codec_dup(codec))) {
            rc = codec_set_to(codec, pBt);
        } else {
            /* Main database codec unavailable */
            rc = SQLITE_CANTOPEN;
        }
    }
    sqlite3_mutex_leave(db->mutex);

    return rc;
}

/* Returns the main database if there is no match */
static int db_index_of(sqlite3 *db, const char *zDbName)
{
    int i;
    if (zDbName) {
        for (i = 0; i < db->nDb; i++) {
            if (!strcmp(db->aDb[i].zDbSName, zDbName))
                return i;
        }
    }
    return 0;
}

int sqlite3_key_v2(sqlite3 *db, const char *zDbName, const void *zKey, int nKey)
{
// @@@ added for sqlar. convention seems to be if n=-1, 
// then zkey is null terminated.
	if (nKey == -1) {
		nKey = strlen(zKey);
	}
    return sqlite3CodecAttach(db, db_index_of(db, zDbName), zKey, nKey);
}

int sqlite3_key(sqlite3 *db, const void *zKey, int nKey)
{
    return sqlite3_key_v2(db, "main", zKey, nKey);
}

int sqlite3_rekey_v2(sqlite3 *db, const char *zDbName,
                     const void *zKey, int nKey)
{
    char *err;
    int nDb, rc;
    Btree *pBt;

    if (!db || (!nKey && !zKey))
        return SQLITE_ERROR;

    rc = SQLITE_ERROR;
    sqlite3_mutex_enter(db->mutex);
    if ((pBt = db->aDb[(nDb = db_index_of(db, zDbName))].pBt)) {
        Pgno pgno;
        DbPage *page;
        Codec *reader, *codec;
        Pager *pager = sqlite3BtreePager(pBt);

        reader = sqlite3PagerGetCodec(pager);
        if (!nKey) {
            /* Decrypt */
            if (reader) {
                reader->writer = NULL;
                rc = sqlite3RunVacuumForRekey(&err, db, nDb, 0);
                if (rc == SQLITE_OK) {
                    rc = codec_set_to(NULL, pBt);
                } else {
                    reader->writer = reader->reader;
                }
            } else {
                rc = codec_verify_page1(NULL, pBt);
            }
            goto leave;
        }

        /* Create a codec for the given key */
        if ((codec = codec_new(zKey, nKey))) {
            codec->pagesize = sqlite3BtreeGetPageSize(pBt);
            if ((codec->pagebuf = sqlite3_malloc(codec->pagesize))) {
                chacha20_rng(codec->salt, 16);
                codec_kdf(codec);
            }
        }
        if (!codec || !codec->pagebuf) {
            codec_free(codec);
            rc = SQLITE_NOMEM;
            goto leave;
        }

        if (!reader) {
            /* Encrypt */
            codec->reader = NULL;
            if ((rc = codec_set_to(codec, pBt)) == SQLITE_OK) {
                rc = sqlite3RunVacuumForRekey(&err, db, nDb, PAGE_RESERVED_LEN);
                if (rc == SQLITE_OK) {
                    codec->reader = codec->writer;
                } else {
                    codec_set_to(NULL, pBt);
                }
            }
            goto leave;
        }

        /* Change key (re-encrypt) */
        reader->writer = codec;
        rc = sqlite3BtreeBeginTrans(pBt, 1);
        for (pgno = 1; rc == SQLITE_OK && pgno <= pager->dbSize; pgno++) {
            /* The DB page occupied by the PENDING_BYTE is never used */
            if (pgno == PENDING_BYTE_PAGE(pager))
                continue;
            if ((rc = sqlite3PagerGet(pager, pgno, &page, 0)) == SQLITE_OK) {
                rc = sqlite3PagerWrite(page);
                sqlite3PagerUnref(page);
            }
        }
        if (rc == SQLITE_OK) {
            sqlite3BtreeCommit(pBt);
            rc = codec_set_to(codec, pBt);
        } else {
            reader->writer = reader;
            sqlite3BtreeRollback(pBt, SQLITE_ABORT_ROLLBACK, 0);
        }
    }

leave:
    sqlite3_mutex_leave(db->mutex);
    return rc;
}

int sqlite3_rekey(sqlite3 *db, const void *zKey, int nKey)
{
    return sqlite3_rekey_v2(db, "main", zKey, nKey);
}

void sqlite3_activate_see(const char *info)
{
}

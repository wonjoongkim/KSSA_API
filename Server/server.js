require("dotenv").config();
const express = require("express");
const fs = require("fs");
const cors = require("cors");
const mariadb = require("mariadb");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const publicPath = path.join(__dirname, "public/uploads/");
const { v4: uuidv4 } = require("uuid"); // UUID 생성을 위한 라이브러리
const mime = require("mime-types");
//#############################################################
//###################    Setting Start   ######################
//#############################################################

const app = express();
const port = 8181;
const secretKey = process.env.SECRETKEY;

//=============================================================
// Cors Start
const corsOptions = {
  origin: process.env.ORIGIN,
};
// Cors End
//=============================================================

//=============================================================
// MariaDB 정보 설정 Start
const pool = mariadb.createPool({
  host: process.env.KSSA_DB_HOST,
  user: process.env.KSSA_DB_USER,
  password: process.env.KSSA_DB_PASSWORD,
  database: process.env.KSSA_DB_DATABASE,
});
// MariaDB 정보 설정 End
//=============================================================

// Helper function for replacer
const replacer = (key, value) =>
  typeof value === "bigint" ? value.toString() : value;

app.use(bodyParser.json({ limit: "350mb" }));
app.use(bodyParser.urlencoded({ limit: "350mb", extended: true }));
app.use(cors({ origin: "*" }));

//=============================================================
// 미들웨어 함수를 사용하여 토큰 검증 Start
const verifyBearerToken = (req, res, next) => {
  const tokenHeader = req.headers["authorization"];
  const accessToken = tokenHeader && tokenHeader.split(" ")[1];
  if (!accessToken) {
    return (
      // .status(401)
      // .json({ error: "Unauthorized - Bearer token missing", RET_CODE: "0001" });
      res.json({
        error: "Unauthorized - Bearer token missing",
        RET_DATA: {},
        RET_CODE: "0001",
      })
    );
  }

  jwt.verify(accessToken, secretKey, (err, decoded) => {
    if (err) {
      return res
        .status(403)
        .json({ error: "Token is not valid", RET_DATA: [], RET_CODE: "0001" });
    }

    req.user = decoded; // Attach user information to the request object
    next(); // Proceed to the next middleware
  });
};
// 미들웨어 함수를 사용하여 토큰 검증 End
//=============================================================

//=============================================================
// 보호된 엔드포인트 Start
app.post("/api/protected", verifyBearerToken, (req, res) => {
  res.json({ message: "Protected data", user: req.user });
});
// 보호된 엔드포인트 End
//=============================================================

//=============================================================
// 비밀번호 해시 생성, 검증 Start
async function hashPassword(password) {
  try {
    // 솔트 생성
    const salt = await bcrypt.genSalt(10); // 라운드 수를 조절 10

    // 비밀번호 해시 생성
    const hashedPassword = await bcrypt.hash(password, salt);

    return hashedPassword;
  } catch (error) {
    console.error("Error hashing password:", error);
    throw error;
  }
}

// 비밀번호 검증
async function verifyPassword(password, hashedPassword) {
  try {
    // 저장된 해시와 입력된 비밀번호를 비교하여 일치 여부를 반환
    return await bcrypt.compare(password, hashedPassword);
  } catch (error) {
    console.error("Error verifying password:", error);
    throw error;
  }
}
// 비밀번호 해시 생성, 검증 End
//=============================================================

//=============================================================
// 업로드된 파일을 저장할 디렉토리 설정 / 미들웨어 Start
const storage = multer.diskStorage({
  dest: "public/uploads/",
  destination: function (req, file, cb) {
    cb(null, "public/uploads/");
  },
  filename: function (req, file, cb) {
    const uniqueFileName = uuidv4(); // 고유한 파일 이름 생성
    const fileExtension = path.extname(file.originalname); // 파일 확장자 추출
    const fileName = `${uniqueFileName}${fileExtension}`; // 고유한 파일 이름에 확장자 추가
    cb(null, fileName);
  },
});
// 업로드된 파일을 저장할 디렉토리 설정 / 미들웨어 End
//=============================================================

//#############################################################
//####################    Setting End   #######################
//#############################################################

//#############################################################
//####################    Common Start    #####################
//#############################################################

const upload = multer({ storage: storage }).array("files", 20);
app.post("/FileUpload", verifyBearerToken, async (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "파일 업로드에 실패했습니다." });
    }
    const { FileKey } = req.body;
    let conn;
    try {
      conn = await pool.getConnection();
      const files = req.files;
      const File_Key = FileKey;
      const insertedFiles = [];
      for (const file of files) {
        // const Original_FileName = decodeURIComponent(file.originalname);
        const Original_FileName = file.originalname;
        const Save_FileName = file.filename;
        // const File_Path = file.path;
        const File_Ext = file.originalname.split(".").pop();
        const File_Size = file.size;
        const File_query =
          "INSERT INTO NKSSA_FileAttach (File_Key, Original_FileName, Save_FileName, File_Path, File_Ext, File_Size) VALUES (?, ?, ?, ?, ?, ? )";
        const result = await conn.query(File_query, [
          File_Key,
          Original_FileName,
          Save_FileName,
          `http://localhost:3001/uploads/${Save_FileName}`,
          File_Ext,
          File_Size,
        ]);
        insertedFiles.push({
          FileKey: File_Key,
          FileNm: Save_FileName,
          FileOrignal: Original_FileName,
          FileIdx: Number(result.insertId),
        });
      }
      res.json({
        RET_DATA: insertedFiles,
        RET_DESC: "파일 업로드에 성공했습니다.",
        RET_CODE: "0000",
      });
    } catch (error) {
      console.error("파일 저장 중 오류 발생:", error);
      res.json({
        RET_DATA: null,
        RET_DESC: `파일 업로드 실패_${err}`,
        RET_CODE: "1000",
      });
    }
  });
});

app.post("/FileDelete", verifyBearerToken, async (req, res) => {
  // app.post('/FileDelete', async (req, res) => {
  const File_Key = req.body.File_Key;
  const Save_FileName = req.body.Save_FileName;
  let conn;
  try {
    conn = await pool.getConnection();
    // 파일을 디스크에서 삭제

    fs.unlink(`public/uploads/${Save_FileName}`, async (err) => {
      if (err) {
        console.error("파일 삭제 중 오류 발생:", err);
        return res
          .status(500)
          .json({ message: "파일 삭제 중 오류가 발생했습니다." });
      }
      // 데이터베이스에서 파일 정보 삭제
      const deleteFileQuery =
        "Delete From NKSSA_FileAttach Where Save_FileName = ?";
      await conn.query(deleteFileQuery, [Save_FileName]);

      const deleteFileSelect =
        "Select File_Key, Original_FileName, Save_FileName, File_Path, File_Ext, File_Size From NKSSA_FileAttach Where File_Key = ?";
      const file_result = await conn.query(deleteFileSelect, [File_Key]);
      res.json({
        RET_DATA: file_result,
        RET_DESC: "파일삭제 성공",
        RET_CODE: "0000",
      });
    });
  } catch (err) {
    console.error("파일 삭제 중 오류 발생:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `파일삭제 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});

// 다운로드 API
app.post("/FileDownLoad", verifyBearerToken, (req, res) => {
  const fileName = req.body.fileName;
  const filePath = path.join(__dirname, "../public/uploads/", fileName); // 파일이 저장된 경로로 변경

  // 파일이 존재하는지 확인
  if (fs.existsSync(filePath)) {
    const mimeType = mime.lookup(filePath); // 파일의 MIME 유형 가져오기
    if (mimeType) {
      res.setHeader("Content-Type", mimeType); // MIME 유형 설정
    }

    // 파일이 존재하면 다운로드 시작
    res.download(filePath, fileName, (err) => {
      if (err) {
        console.error("파일 다운로드 중 오류 발생:", err);
        res
          .status(500)
          .json({ error: "파일을 다운로드하는 동안 오류가 발생했습니다." });
      }
    });
  } else {
    // 파일이 존재하지 않으면 404 에러 반환
    res.status(404).json({ error: "파일을 찾을 수 없습니다." });
  }
});

// 미리보기 API
app.post("/FilePreView", (req, res) => {
  const fileName = req.body.fileName;
  // const filePath = path.join(__dirname, '../public/uploads/', fileName); // 파일이 저장된 경로로 변경
  const filePath = path.join(fileName); // 파일이 저장된 경로로 변경

  console.log(filePath);
  if (fs.existsSync(filePath)) {
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
  } else {
    // 파일이 존재하지 않으면 404 에러 반환
    res.status(404).json({ error: "파일을 찾을 수 없습니다." });
  }
});
//#############################################################
//#####################    Common End    ######################
//#############################################################

//#############################################################
//#####################     Adm Start   #######################
//#############################################################

//=============================================================
// 관리자 로그인 완료시 토큰 발행 Start
app.post("/Adm/Admin_Login", async (req, res) => {
  const admid = req.body.admid;
  const admpw = req.body.admpw;
  let conn;
  try {
    conn = await pool.getConnection();
    const query = `Select Adm_Id, Adm_Pw, Adm_Name, Adm_Lv, State, InDate FROM NKSSA_Manager Where Adm_Id = ?`;
    const rows = await conn.query(query, [admid]);

    // 사용자가 존재하지 않는 경우
    if (rows.length === 0) {
      res.json({
        RET_DATA: null,
        RET_DESC: "입력하신 정보는 가입되어 있지 않습니다.",
        RET_CODE: "1000",
      });
    }

    const user = rows[0];
    const hashedPassword = user.Adm_Pw;
    // 입력된 비밀번호와 저장된 해시된 비밀번호 비교
    bcrypt.compare(admpw, hashedPassword, function (err, result) {
      if (err) {
        console.error("비밀번호를 체크하는 중에 오류가 발생했습니다.:", err);
        res.json({
          RET_DATA: null,
          RET_DESC: "비밀번호를 체크하는 중에 오류가 발생했습니다.",
          RET_CODE: "2000",
        });
      } else if (result) {
        // 비밀번호 일치
        const accessToken = jwt.sign(
          {
            Adm_Id: user.Adm_Id,
            Adm_Name: user.Adm_Name,
          },
          secretKey,
          { expiresIn: "1h" }
        );
        res.json({
          RET_DATA: {
            accessToken,
            Adm_Id: user.Adm_Id,
            Adm_Name: user.Adm_Name,
          },
          RET_DESC: "성공",
          RET_CODE: "0000",
        });
      } else {
        // 비밀번호 불일치
        console.error("입력하신 비밀번호가 맞지 않습니다.:", err);
        res.json({
          RET_DATA: null,
          RET_DESC: "입력하신 비밀번호가 맞지 않습니다.",
          RET_CODE: "2000",
        });
      }
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `로그인 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) await conn.end();
  }
});
// 관리자 로그인 완료시 토큰 발행 End
//=============================================================

// =============================================================
// 관리자 정보 Start
app.post("/Adm/Admin_Info", verifyBearerToken, async (req, res) => {
  const { Adm_Id, Adm_Name } = req.user;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Adm_Id, Adm_Name From NKSSA_Manager Where Adm_Id = ? And Adm_Name = ? ";
    const result = await conn.query(query, [Adm_Id, Adm_Name]);

    res.json({
      RET_DATA: {
        Adm_Id: result[0].Adm_Id,
        Adm_Name: result[0].Adm_Name,
      },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// 관리자 정보 End
// =============================================================

//=============================================================
// 관리자 등록 Start
app.post("/Adm/Adm_Insert", async (req, res) => {
  const { Adm_Id, Adm_Pw, Adm_Name } = req.body;
  const hashedPassword = await hashPassword(Adm_Pw); // 비밀번호 해시 생성
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Insert Into NKSSA_Manager (Adm_Id, Adm_Pw, Adm_Name) Values (?, ?, ?)";
    const result = await conn.query(query, [Adm_Id, hashedPassword, Adm_Name]);
    res.json({
      RET_DATA: null,
      RET_DESC: "저장 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `저장 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    // if (conn) return conn.end();
    if (conn) conn.release();
  }
});
// 관리자 등록 End
//=============================================================

//=============================================================
// 회원 List Start
app.post("/Adm/Member_List", verifyBearerToken, async (req, res) => {
  const { Member_Search } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query = `Select 
            ( SELECT CAST(COUNT(Idx) AS UNSIGNED) FROM NKSSA_Members WHERE CONCAT(User_Nm, User_Id, User_Phone, User_Email, User_Type, InDate) like ?) AS Total
            , Idx, User_Id, User_Type, User_Nm, User_Phone, User_Email, InDate, Visited FROM 
            NKSSA_Members WHERE CONCAT(User_Nm, User_Id, User_Phone, User_Email, User_Type, InDate) like ?`;
    const result = await conn.query(query, [
      `%${Member_Search}%`,
      `%${Member_Search}%`,
    ]);
    const serializedResult = result.map((row) => ({
      Total: String(row.Total),
      Idx: row.Idx,
      User_Nm: row.User_Nm,
      User_Id: row.User_Id,
      User_Phone: row.User_Phone,
      User_Email: row.User_Email,
      User_Type: row.User_Type,
      InDate: row.InDate,
      Visited: row.Visited,
    }));
    res.json({
      RET_DATA: serializedResult,
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// 회원 List End
//=============================================================

//=============================================================
// Contens List Start
app.post("/Adm/Contets_List", async (req, res) => {
  const { Contents_Type } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Contents From NKSSA_Contents Where Contents_Type = ? ";
    const result = await conn.query(query, [Contents_Type]);

    res.json({
      RET_DATA: { result },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Contens List End
//=============================================================

//=============================================================
// Contents 등록 Start
app.post("/Adm/Contets_Insert", verifyBearerToken, async (req, res) => {
  const { Contents_Type, Contents } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Insert Into NKSSA_Contents (Contents_Type, Contents) " +
      "Values " +
      "(?, ?)";
    const result = await conn.query(query, [Contents_Type, Contents]);
    res.json({
      RET_DATA: null,
      RET_DESC: "저장 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `저장 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Contents 등록 End
//=============================================================

//=============================================================
// Contents 수정 Start
app.post("/Adm/Contets_Update", verifyBearerToken, async (req, res) => {
  const { Contents_Type, Contents, Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Update NKSSA_Contents set Contents_Type = ?, Contents = ? " +
      "Where Idx = ? ";
    const result = await conn.query(query, [Contents_Type, Contents, Idx]);
    res.json({
      RET_DATA: null,
      RET_DESC: "수정 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `수정 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Contents 수정 End
//=============================================================

//=============================================================
// Board List Start
app.post("/Adm/Board_List", async (req, res) => {
  const { Board_Type, Board_Search } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query = `Select (
            SELECT CAST(COUNT(Idx) AS UNSIGNED) 
            FROM NKSSA_Board 
            WHERE Board_Type = ?
        ) AS Total, Idx, Board_Type, Subject, Contents, File_Key, Visited, State, InDate From NKSSA_Board Where Board_Type = ? And Subject like ?`;
    const result = await conn.query(query, [
      Board_Type,
      Board_Type,
      `%${Board_Search}%`,
    ]);
    const serializedResult = result.map((row) => ({
      Total: String(row.Total),
      Idx: row.Idx,
      Board_Type: row.Board_Type,
      Subject: row.Subject,
      Contents: row.Contents,
      File_Key: row.File_Key,
      Visited: row.Visited,
      State: row.State,
      InDate: row.InDate,
    }));

    res.json({
      RET_DATA: serializedResult,
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Board List End
//=============================================================

//=============================================================
// Board View Start
app.post("/Adm/Board_View", async (req, res) => {
  const { Board_Type, Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    // 게시물 조회
    const query =
      "Select Board_Type, Subject, Contents, File_Key, Visited, State, InDate From NKSSA_Board Where Board_Type = ? And Idx = ?";
    const result = await conn.query(query, [Board_Type, Idx]);

    // 파일 조회
    const file_query =
      "Select File_Key, Original_FileName, Save_FileName, File_Path, File_Ext, File_Size From NKSSA_FileAttach Where File_Key = ?";
    const file_result = await conn.query(file_query, [result[0].File_Key]);
    res.json({
      RET_DATA: { result, file_result },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Board View End
//=============================================================

//=============================================================
// Board 등록 Start
app.post("/Adm/Board_Insert", verifyBearerToken, async (req, res) => {
  const { Board_Type, Subject, Contents, FileKey, InDate } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "INSERT INTO NKSSA_Board (Board_Type, Subject, Contents, File_Key, InDate) VALUES (?, ?, ?, ?, ?)";
    const result = await conn.query(query, [
      Board_Type,
      Subject,
      Contents,
      FileKey,
      InDate,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "저장 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `저장 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Board 등록 End
//=============================================================

//=============================================================
// Board 수정 Start
app.post("/Adm/Board_Update", verifyBearerToken, async (req, res) => {
  // const { Subject, Contents, InDate, State, Idx, Board_Type } = req.body;
  const { Subject, Contents, State, Idx, Board_Type } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    // const query = 'Update NKSSA_Board set Subject = ?, Contents = ?, InDate = ?, State = ? where Idx = ? and Board_Type = ?';
    // const result = await conn.query(query, [Subject, Contents, InDate + ' 23:59:59.000', State, Idx, Board_Type]);
    const query =
      "Update NKSSA_Board set Subject = ?, Contents = ?, State = ? where Idx = ? and Board_Type = ?";
    const result = await conn.query(query, [
      Subject,
      Contents,
      State,
      Idx,
      Board_Type,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "수정 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `수정 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Board 수정 End
//=============================================================

//=============================================================
// Board 삭제 Start
app.post("/Adm/Board_Delete", verifyBearerToken, async (req, res) => {
  const { Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    for (const idx of Idx) {
      // NKSSA_Board 테이블에서 해당 Idx의 File_Key를 가져옴
      const File_Q = `SELECT File_Key FROM NKSSA_Board WHERE Idx = ${idx}`;
      const Result_Q = await conn.query(File_Q);

      if (Result_Q.length > 0) {
        const File_N = `SELECT Save_FileName FROM NKSSA_FileAttach WHERE File_Key = '${Result_Q[0].File_Key}'`;
        const Result_N = await conn.query(File_N);

        if (Result_N.length > 0) {
          const File_D = `DELETE FROM NKSSA_FileAttach WHERE File_Key = '${Result_Q[0].File_Key}'`;
          await conn.query(File_D);

          fs.unlink(`uploads/${Result_N[0].Save_FileName}`, async (err) => {
            if (err) {
              console.error("파일 삭제 중 오류 발생:", err);
              return res
                .status(500)
                .json({ message: "파일 삭제 중 오류가 발생했습니다." });
            }
            // 데이터베이스에서 파일 정보 삭제
            const deleteFileQuery = `Delete From NKSSA_FileAttach Where File_Key = '${Result_Q[0].File_Key}'`;
            await conn.query(deleteFileQuery);
          });
        }
      }

      // NKSSA_Board 테이블에서 해당 Idx의 데이터를 삭제
      const query = `DELETE FROM NKSSA_Board WHERE Idx = ${idx}`;
      await conn.query(query);
    }

    res.json({
      RET_DATA: null,
      RET_DESC: "삭제 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `삭제 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Board 삭제 End
//=============================================================

//=============================================================
// Picture List Start
app.post("/Adm/Picture_List", async (req, res) => {
  const { Board_Type, Board_Search } = req.body;
  let conn;

  const query = `Select (
        SELECT CAST(COUNT(Idx) AS UNSIGNED) 
        FROM NKSSA_Board 
        WHERE Board_Type = ?
    ) AS Total, Idx, Board_Type, Subject, Contents, File_Key, Visited, InDate, Unit From NKSSA_Board Where Board_Type = ? And State = '0' And Subject like ?`;

  try {
    conn = await pool.getConnection();
    const result = await conn.query(query, [
      Board_Type,
      Board_Type,
      `%${Board_Search}%`,
    ]); // 게시물 조회

    const file_query =
      "Select File_Path From NKSSA_FileAttach Where File_Key = ?"; // 파일 조회

    // 결과를 담을 배열 선언
    const resultsWithFiles = [];

    for (const row of result) {
      const file_result = await conn.query(file_query, row.File_Key);

      resultsWithFiles.push({
        ...row,
        Total: String(row.Total),
        Idx: row.Idx,
        Board_Type: row.Board_Type,
        Subject: row.Subject,
        Contents: row.Contents,
        File_Key: row.File_Key,
        Visited: row.Visited,
        InDate: row.InDate,
        Unit: row.Unit,
        Images: file_result,
      });
    }
    res.json({
      RET_DATA: { resultsWithFiles },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Picture List End
//=============================================================

//=============================================================
// Picture 등록 Start
app.post("/Adm/Picture_Insert", verifyBearerToken, async (req, res) => {
  const { Board_Type, Subject, Contents, FileKey, InDate, Unit } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "INSERT INTO NKSSA_Board (Board_Type, Subject, Contents, File_Key, InDate, Unit) VALUES (?, ?, ?, ?, ?, ?)";
    const result = await conn.query(query, [
      Board_Type,
      Subject,
      Contents,
      FileKey,
      InDate,
      Unit,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "저장 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `저장 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Picture 등록 End
//=============================================================

//=============================================================
// Picture 수정 Start
app.post("/Adm/Picture_Update", verifyBearerToken, async (req, res) => {
  const { Subject, Contents, State, Unit, Idx, Board_Type } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Update NKSSA_Board set Subject = ?, Contents = ?, State = ?, Unit = ? where Idx = ? and Board_Type = ?";
    const result = await conn.query(query, [
      Subject,
      Contents,
      State,
      Unit,
      Idx,
      Board_Type,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "수정 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `수정 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Picture 수정 End
//=============================================================

//=============================================================
// Picture 삭제 Start
app.post("/Adm/Picture_Delete", verifyBearerToken, async (req, res) => {
  const { Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    for (const idx of Idx) {
      // NKSSA_Board 테이블에서 해당 Idx의 File_Key를 가져옴
      const File_Q = `SELECT File_Key FROM NKSSA_Board WHERE Idx = ${idx}`;
      const Result_Q = await conn.query(File_Q);

      if (Result_Q.length > 0) {
        const File_N = `SELECT Save_FileName FROM NKSSA_FileAttach WHERE File_Key = '${Result_Q[0].File_Key}'`;
        const Result_N = await conn.query(File_N);

        if (Result_N.length > 0) {
          const File_D = `DELETE FROM NKSSA_FileAttach WHERE File_Key = '${Result_Q[0].File_Key}'`;
          await conn.query(File_D);

          fs.unlink(`uploads/${Result_N[0].Save_FileName}`, async (err) => {
            if (err) {
              console.error("파일 삭제 중 오류 발생:", err);
              return res
                .status(500)
                .json({ message: "파일 삭제 중 오류가 발생했습니다." });
            }
            // 데이터베이스에서 파일 정보 삭제
            const deleteFileQuery = `Delete From NKSSA_FileAttach Where File_Key = '${Result_Q[0].File_Key}'`;
            await conn.query(deleteFileQuery);
          });
        }
      }

      // NKSSA_Board 테이블에서 해당 Idx의 데이터를 삭제
      const query = `DELETE FROM NKSSA_Board WHERE Idx = ${idx}`;
      await conn.query(query);
    }

    res.json({
      RET_DATA: null,
      RET_DESC: "삭제 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `삭제 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Picture 삭제 End
//=============================================================

//=============================================================
// Calender Schedule Start
app.post("/Adm/Calender_Schedule", verifyBearerToken, async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, Edu_State, InDate From NKSSA_Calender";
    const result = await conn.query(query, []);
    res.json({
      RET_DATA: result,
      RET_DESC: "조회 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender Schedule End
//=============================================================

//=============================================================
// Calender List Start
app.post("/Adm/Calender_List", verifyBearerToken, async (req, res) => {
  const { Calender_Search } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();

    // 검색어가 날짜인지 확인
    const isDate = !isNaN(Date.parse(Calender_Search));

    let query;
    let result;

    if (isDate) {
      query = `Select ( SELECT CAST(COUNT(Idx) AS UNSIGNED) FROM NKSSA_Calender WHERE ? BETWEEN Edu_Date_Start AND Edu_Date_End) AS Total
            , Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, Edu_State, InDate FROM 
            NKSSA_Calender WHERE ? BETWEEN Edu_Date_Start AND Edu_Date_End`;
      result = await conn.query(query, [Calender_Search, Calender_Search]);
    } else {
      query = `Select ( SELECT CAST(COUNT(Idx) AS UNSIGNED) FROM NKSSA_Calender WHERE CONCAT(Edu_Nm, Edu_Type, Base_Line, Edu_State) like ?) AS Total
            , Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, Edu_State, InDate FROM 
            NKSSA_Calender WHERE CONCAT(Edu_Nm, Edu_Type, Base_Line, Edu_State) like ?`;
      result = await conn.query(query, [
        `%${Calender_Search}%`,
        `%${Calender_Search}%`,
      ]);
    }
    const serializedResult = result.map((row) => ({
      Total: String(row.Total),
      Idx: row.Idx,
      Edu_Nm: row.Edu_Nm,
      Edu_Type: row.Edu_Type,
      Base_Line: row.Base_Line,
      Edu_Date_Start: row.Edu_Date_Start,
      Edu_Date_End: row.Edu_Date_End,
      Edu_Personnel: row.Edu_Personnel,
      Edu_State: row.Edu_State,
      InDate: row.InDate,
    }));

    res.json({
      RET_DATA: serializedResult,
      RET_DESC: "조회 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender List End
//=============================================================

//=============================================================
// Calender View Start
app.post("/Adm/Calender_View", verifyBearerToken, async (req, res) => {
  const { Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, Edu_State, InDate From NKSSA_Calender Where Idx = ?";
    const result = await conn.query(query, [Idx]);
    res.json({
      RET_DATA: result,
      RET_DESC: "조회 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender View End
//=============================================================

//=============================================================
// Calender Delete Start
app.post("/Adm/Calender_Delete", verifyBearerToken, async (req, res) => {
  const { Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query = `Delete from NKSSA_Calender Where Idx = ?`;
    const result = await conn.query(query, [Idx]);
    res.json({
      RET_DATA: null,
      RET_DESC: "삭제 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);

    res.json({
      RET_DATA: null,
      RET_DESC: `삭제 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender Delete End
//=============================================================

//=============================================================
// Calender Insert Start
app.post("/Adm/Calender_Insert", verifyBearerToken, async (req, res) => {
  const {
    Edu_Nm,
    Edu_Type,
    Base_Line,
    Edu_Date_Start,
    Edu_Date_End,
    Edu_Personnel,
  } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "INSERT INTO NKSSA_Calender ( Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel ) VALUES (?, ?, ?, ?, ?, ?)";
    const result = await conn.query(query, [
      Edu_Nm,
      Edu_Type,
      Base_Line,
      `${Edu_Date_Start} 00:00:00`,
      `${Edu_Date_End} 24:00:00`,
      Edu_Personnel,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "저장 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `저장 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender Insert End
//=============================================================

//=============================================================
// Calender Update Start
app.post("/Adm/Calender_Update", verifyBearerToken, async (req, res) => {
  const {
    Edu_Nm,
    Edu_Type,
    Base_Line,
    Edu_Date_Start,
    Edu_Date_End,
    Edu_Personnel,
    Edu_State,
    Idx,
  } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Update NKSSA_Calender Set Edu_Nm = ?, Edu_Type = ?, Base_Line = ?, Edu_Date_Start = ?, Edu_Date_End = ?, Edu_Personnel = ?, Edu_State = ? Where Idx = ?";
    const result = await conn.query(query, [
      Edu_Nm,
      Edu_Type,
      Base_Line,
      `${Edu_Date_Start} 00:00:00`,
      `${Edu_Date_End} 24:00:00`,
      Edu_Personnel,
      Edu_State,
      Idx,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "수정 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `수정 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender Update End
//=============================================================

//=============================================================
// Calender State처리 Start
app.post("/Adm/Calender_State", verifyBearerToken, async (req, res) => {
  const { Edu_State, Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query = "Update NKSSA_Calender Set Edu_State = ? Where Idx = ?";
    const result = await conn.query(query, [Edu_State, Idx]);
    res.json({
      RET_DATA: null,
      RET_DESC: "상태처리 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `상태처리 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender State처리 End
//=============================================================

//=============================================================
// Calender List Start
app.post("/Adm/Calender_YearPlan", verifyBearerToken, async (req, res) => {
  const { YearPlan } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, InDate From NKSSA_Calender Where YEAR(Edu_Date_Start) = ? Order By Edu_Date_Start";
    const result = await conn.query(query, [YearPlan]);

    res.json({
      RET_DATA: result.map((row) => ({
        Idx: row.Idx,
        Edu_Nm: row.Edu_Nm,
        Edu_Type: row.Edu_Type,
        Base_Line: row.Base_Line,
        Edu_Date_SM: (1 + row.Edu_Date_Start.getMonth())
          .toString()
          .padStart(2, "0"),
        Edu_Date_SD: row.Edu_Date_Start.getDate().toString().padStart(2, "0"),
        Edu_Date_EM: (1 + row.Edu_Date_End.getMonth())
          .toString()
          .padStart(2, "0"),
        Edu_Date_ED: row.Edu_Date_End.getDate().toString().padStart(2, "0"),
        Edu_Personnel: row.Edu_Personnel,
        InDate: row.InDate,
      })),
      RET_DESC: "검색 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `검색 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender List End
//=============================================================

//#############################################################
//######################     Adm End   ########################
//#############################################################

//#############################################################
//#####################    USER Start   #######################
//#############################################################

//=============================================================
// 회원가입시 아이디 중복 체크 Start
app.post("/User/DupliChk", async (req, res) => {
  const user_id = req.body.user_id;
  let conn;
  try {
    conn = await pool.getConnection();
    const query = `Select User_Id FROM NKSSA_Members Where User_Id = ?`;
    const rows = await conn.query(query, [user_id]);

    // 사용자가 존재하지 않는 경우
    if (rows.length === 0) {
      res.json({
        RET_DATA: rows.User_Id,
        RET_DESC: "사용가능",
        RET_CODE: "0000",
      });
    } else {
      res.json({
        RET_DATA: null,
        RET_DESC: "입력하신 아이디는 가입되어 있습니다.",
        RET_CODE: "1000",
      });
    }
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `중복 체크 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) await conn.end();
  }
});

// 회원가입시 아이디 중복 체크 End
//=============================================================

//=============================================================
// 로그인 완료시 토큰 발행 Start
app.post("/User/Member_Login", async (req, res) => {
  const userid = req.body.userid;
  const userpw = req.body.userpw;
  let conn;
  try {
    conn = await pool.getConnection();
    const query = `Select User_Id, User_Nm, User_Pw FROM NKSSA_Members Where User_Id = ?`;
    const rows = await conn.query(query, [userid]);

    // 사용자가 존재하지 않는 경우
    if (rows.length === 0) {
      res.json({
        RET_DATA: null,
        RET_DESC: "입력하신 정보는 가입되어 있지 않습니다.",
        RET_CODE: "1000",
      });
    }
    const user = rows[0];
    const hashedPassword = user.User_Pw;
    // 입력된 비밀번호와 저장된 해시된 비밀번호 비교
    bcrypt.compare(userpw, hashedPassword, function (err, result) {
      if (err) {
        console.error("비밀번호를 체크하는 중에 오류가 발생했습니다.:", err);
        res.json({
          RET_DATA: null,
          RET_DESC: "비밀번호를 체크하는 중에 오류가 발생했습니다.",
          RET_CODE: "2000",
        });
      } else if (result) {
        // 비밀번호 일치
        const accessToken = jwt.sign(
          {
            User_Id: user.User_Id,
            User_Nm: user.User_Nm,
          },
          secretKey,
          { expiresIn: "1h" }
        );
        res.json({
          RET_DATA: {
            accessToken,
            User_Id: user.User_Id,
            User_Nm: user.User_Nm,
          },
          RET_DESC: "성공",
          RET_CODE: "0000",
        });
      } else {
        // 비밀번호 불일치
        console.error("입력하신 비밀번호가 맞지 않습니다.:", err);
        res.json({
          RET_DATA: null,
          RET_DESC: "입력하신 비밀번호가 맞지 않습니다.",
          RET_CODE: "2000",
        });
      }
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `로그인 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) await conn.end();
  }
});
// 로그인 완료시 토큰 발행 End
//=============================================================

//=============================================================
// 로그인한 회원 정보 Start
app.post("/User/Member_Info", verifyBearerToken, async (req, res) => {
  const { User_Id, User_Nm } = req.user;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select User_Id, User_Nm, User_Phone, User_Email, User_Zip, User_Address, User_Address_Detail, Edu_Id, Edu_Nm, InDate From NKSSA_Members Where User_Id = ? And User_Nm = ? ";
    const result = await conn.query(query, [User_Id, User_Nm]);

    res.json({
      RET_DATA: {
        User_Id: result[0].User_Id,
        User_Nm: result[0].User_Nm,
        User_Phone: result[0].User_Phone,
        User_Email: result[0].User_Email,
        User_Zip: result[0].User_Zip,
        User_Address: result[0].User_Address,
        User_Address_Detail: result[0].User_Address_Detail,
        Edu_Id: result[0].Edu_Id,
        Edu_Nm: result[0].Edu_Nm,
        InDate: result[0].InDate,
      },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// 로그인한 회원 정보 End
//=============================================================

//=============================================================
// 회원 등록 Start
app.post("/User/Member_Insert", async (req, res) => {
  const {
    User_Id,
    User_Pw,
    User_Type,
    Edu_Nm,
    Edu_Id,
    User_Nm,
    User_Phone,
    User_Email,
    User_Zip,
    User_Address,
    User_Address_Detail,
    Company_Nm,
    Company_Zip,
    Company_Address,
    Company_Address_Detail,
    Manager_Nm,
    Manager_Phone,
    Manager_Email,
    Edu_No,
    Edu_Code,
    Edu_Code_Nm,
  } = req.body;
  const hashedPassword = await hashPassword(User_Pw); // 비밀번호 해시 생성
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Insert Into NKSSA_Members (User_Id, User_Pw, User_Type, Edu_Nm, Edu_Id, User_Nm, User_Phone, User_Email, User_Zip " +
      ", User_Address, User_Address_Detail, Company_Nm, Company_Zip, Company_Address, Company_Address_Detail, Manager_Nm " +
      ", Manager_Phone, Manager_Email, Edu_No, Edu_Code, Edu_Code_Nm) " +
      "Values " +
      "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    const result = await conn.query(query, [
      User_Id,
      hashedPassword,
      User_Type,
      Edu_Nm,
      Edu_Id,
      User_Nm,
      User_Phone,
      User_Email,
      User_Zip,
      User_Address,
      User_Address_Detail,
      Company_Nm,
      Company_Zip,
      Company_Address,
      Company_Address_Detail,
      Manager_Nm,
      Manager_Phone,
      Manager_Email,
      Edu_No,
      Edu_Code,
      Edu_Code_Nm,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "저장 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `저장 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    // if (conn) return conn.end();
    if (conn) conn.release();
  }
});
// 회원 등록 End
//=============================================================

//=============================================================
// 회원 정보 수정 Start
app.post("/User/Member_Update", verifyBearerToken, async (req, res) => {
  const {
    Edu_Nm,
    Edu_Id,
    User_Nm,
    User_Phone,
    User_Email,
    User_Zip,
    User_Address,
    User_Address_Detail,
    Company_Nm,
    Company_Zip,
    Company_Address,
    Company_Address_Detail,
    Manager_Nm,
    Manager_Phone,
    Manager_Email,
    Idx,
  } = req.body;

  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Update NKSSA_Members set Edu_Nm = ?, Edu_Id = ?, User_Nm = ?, User_Phone = ?, User_Email = ?, User_Zip = ? " +
      ", User_Address = ?, User_Address_Detail = ?, Company_Nm = ?, Company_Zip = ?, Company_Address = ?, Company_Address_Detail = ?, Manager_Nm = ? " +
      ", Manager_Phone = ?, Manager_Email = ? " +
      "Where Idx = ? ";
    const result = await conn.query(query, [
      Edu_Nm,
      Edu_Id,
      User_Nm,
      User_Phone,
      User_Email,
      User_Zip,
      User_Address,
      User_Address_Detail,
      Company_Nm,
      Company_Zip,
      Company_Address,
      Company_Address_Detail,
      Manager_Nm,
      Manager_Phone,
      Manager_Email,
      Idx,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "수정 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `수정 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// 회원 정보 수정 End
//=============================================================

//=============================================================
// MyPage 교육 상세정보 Start
app.post("/XBT/MyPage_Edu_Detail", async (req, res) => {
  const { User_Id, Proc_Cd } = req.body;
  let conn;
  try {
    conn = await XBTpool.getConnection();
    //-- XBT 평가
    const XBT_QUERY = `Select INSERT_DATE, (RIGHT_CNT + WRONG_CNT)AS XBT_Quest_Cnt, RIGHT_CNT AS XBT_Right_Cnt, WRONG_CNT AS XBT_Wrong_Cnt,(RIGHT_CNT * 100 / (RIGHT_CNT + WRONG_CNT)) AS XTB_Avg 
              From XBT_BASELINE_EVALUATION Where USER_ID = ? And PROC_CD = ?`;
    const Xresult = await conn.query(XBT_QUERY, [User_Id, Proc_Cd]);
    const XBTRESULT = Xresult.map((row) => ({
      INSERT_DATE: row.INSERT_DATE,
      XBT_Quest_Cnt: Number(row.XBT_Quest_Cnt),
      XBT_Right_Cnt: Number(row.XBT_Right_Cnt),
      XBT_Wrong_Cnt: Number(row.XBT_Wrong_Cnt),
      XTB_Avg: Number(row.XTB_Avg),
    }));
    //-- 실기 평가
    const PRACTICE_QUERY = `Select INSERT_DATE, PRACTICE_BEFORE_SCORE AS PRACTICE_SCORE From XBT_BASELINE_STUDENT_INFO Where USER_ID = ? And PROC_CD = ?`;
    const Presult = await conn.query(PRACTICE_QUERY, [User_Id, Proc_Cd]);
    const PRACTICERESULT = Presult.map((row) => ({
      INSERT_DATE: row.INSERT_DATE,
      PRACTICE_SCORE: Number(row.PRACTICE_SCORE),
    }));
    //-- 이론 평가
    const THEORY_QUERY = `Select INSERT_DATE, (RIGHT_CNT + WRONG_CNT)AS THEORY_Quest_Cnt, RIGHT_CNT AS THEORY_Right_Cnt, WRONG_CNT AS THEORY_Wrong_Cnt, GAIN_SCORE AS THEORY_Avg
              From XBT_BASELINE_THEORY Where USER_ID = ? And PROC_CD = ?`;
    const Tresult = await conn.query(THEORY_QUERY, [User_Id, Proc_Cd]);
    const THEORYRESULT = Tresult.map((row) => ({
      INSERT_DATE: row.INSERT_DATE,
      THEORY_Quest_Cnt: Number(row.THEORY_Quest_Cnt),
      THEORY_Right_Cnt: Number(row.THEORY_Right_Cnt),
      THEORY_Wrong_Cnt: Number(row.THEORY_Wrong_Cnt),
      THEORY_Avg: Number(row.THEORY_Avg),
    }));
    //-- 항공위험무 평가
    const DANGER_QUERY = `Select INSERT_DATE, (DANGER_RIGHT_CNT + DANGER_WRONG_CNT)AS DANGER_Quest_Cnt, DANGER_RIGHT_CNT AS DANGER_Right_Cnt, DANGER_WRONG_CNT AS DANGER_Wrong_Cnt, 
                  DANGER_SCORE AS DANGER_Avg
                  From XBT_BASELINE_THEORY Where USER_ID = ? And PROC_CD = ?`;
    const Dresult = await conn.query(DANGER_QUERY, [User_Id, Proc_Cd]);
    const DANGERRESULT = Dresult.map((row) => ({
      INSERT_DATE: row.INSERT_DATE,
      DANGER_Quest_Cnt: Number(row.DANGER_Quest_Cnt),
      DANGER_Right_Cnt: Number(row.DANGER_Right_Cnt),
      DANGER_Wrong_Cnt: Number(row.DANGER_Wrong_Cnt),
      DANGER_Avg: Number(row.DANGER_Avg),
    }));

    res.json({
      RET_DATA: { XBTRESULT, PRACTICERESULT, THEORYRESULT, DANGERRESULT },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// MyPage 교육 상세정보 End
//=============================================================

//=============================================================
// Contens List Start
app.post("/User/Contets_List", async (req, res) => {
  const { Contents_Type } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Contents From NKSSA_Contents Where Contents_Type = ? And State = '0' ";
    const result = await conn.query(query, [Contents_Type]);

    res.json({
      RET_DATA: result,
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Contens List End
//=============================================================

//=============================================================
// Board Main List Start
app.post("/User/Board_Main_List", async (req, res) => {
  const { Board_Type } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Board_Type, Subject, InDate From NKSSA_Board Where Board_Type = ? And State = '0' LIMIT 5 ";
    const result = await conn.query(query, [Board_Type]);
    if (result.length !== 0) {
      res.json({
        RET_DATA: result,
        RET_CODE: "0000",
      });
    } else {
      res.json({
        RET_DATA: "No Data",
        RET_CODE: "0001",
      });
    }
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Board Main List End
//=============================================================

//=============================================================
// Board Main View Start
app.post("/User/Board_Main_View", async (req, res) => {
  const { Board_Type, Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    // 게시물 조회
    const query = `Select (
              SELECT CAST(COUNT(Idx) AS UNSIGNED) 
              FROM NKSSA_Board 
              WHERE Board_Type = ?
          ) AS Total, Idx, Board_Type, Subject, Contents, File_Key, Visited, InDate From NKSSA_Board Where Board_Type = ? And Idx = ?`;
    const result = await conn.query(query, [Board_Type, Board_Type, Idx]);
    const serializedResult = result.map((row) => ({
      Total: String(row.Total),
      Board_Type: row.Board_Type,
      Subject: row.Subject,
      Contents: row.Contents,
      File_Key: row.File_Key,
      Visited: row.Visited,
      InDate: row.InDate,
    }));

    // 파일 조회
    const file_query =
      "Select File_Key, Original_FileName, Save_FileName, File_Path, File_Ext, File_Size From NKSSA_FileAttach Where File_Key = ?";
    const file_result = await conn.query(file_query, [
      serializedResult[0].File_Key,
    ]);
    res.json({
      RET_DATA: { serializedResult, file_result },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Board Main View End
//=============================================================

//=============================================================
// Board List Start
app.post("/User/Board_List", async (req, res) => {
  const { Board_Type, Board_Search } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query = `SELECT (
              SELECT CAST(COUNT(Idx) AS UNSIGNED) 
              FROM NKSSA_Board 
              WHERE Board_Type = ?
          ) AS Total, Idx, Board_Type, Subject, Contents, File_Key, Visited, InDate From NKSSA_Board Where Board_Type = ? And State = '0' And Subject like ?`;
    const result = await conn.query(query, [
      Board_Type,
      Board_Type,
      `%${Board_Search}%`,
    ]);
    const serializedResult = result.map((row) => ({
      Total: String(row.Total),
      Idx: row.Idx,
      Board_Type: row.Board_Type,
      Subject: row.Subject,
      Contents: row.Contents,
      File_Key: row.File_Key,
      Visited: row.Visited,
      InDate: row.InDate,
    }));

    res.json({
      RET_DATA: serializedResult,
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Board List End
//=============================================================

//=============================================================
// Board View Start
app.post("/User/Board_View", async (req, res) => {
  const { Board_Type, Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    // 게시물 조회
    const query = `Select (
              SELECT CAST(COUNT(Idx) AS UNSIGNED) 
              FROM NKSSA_Board 
              WHERE Board_Type = ?
          ) AS Total, Idx, Board_Type, Subject, Contents, File_Key, Visited, InDate From NKSSA_Board Where Board_Type = ? And Idx = ?`;
    const result = await conn.query(query, [Board_Type, Board_Type, Idx]);
    const serializedResult = result.map((row) => ({
      Total: String(row.Total),
      Board_Type: row.Board_Type,
      Subject: row.Subject,
      Contents: row.Contents,
      File_Key: row.File_Key,
      Visited: row.Visited,
      InDate: row.InDate,
    }));

    // 파일 조회
    const file_query =
      "Select File_Key, Original_FileName, Save_FileName, File_Path, File_Ext, File_Size From NKSSA_FileAttach Where File_Key = ?";
    const file_result = await conn.query(file_query, [
      serializedResult[0].File_Key,
    ]);
    res.json({
      RET_DATA: { serializedResult, file_result },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Board View End
//=============================================================

//=============================================================
// Picture List Start
app.post("/User/Picture_List", async (req, res) => {
  const { Board_Type, Board_Search } = req.body;
  let conn;

  const query = `Select (
      SELECT CAST(COUNT(Idx) AS UNSIGNED) 
      FROM NKSSA_Board 
      WHERE Board_Type = ?
  ) AS Total, Idx, Board_Type, Subject, Contents, File_Key, Visited, InDate, Unit From NKSSA_Board Where Board_Type = ? And State = '0' And Subject like ?`;

  try {
    conn = await pool.getConnection();
    const result = await conn.query(query, [
      Board_Type,
      Board_Type,
      `%${Board_Search}%`,
    ]); // 게시물 조회

    const file_query =
      "Select File_Path From NKSSA_FileAttach Where File_Key = ?"; // 파일 조회

    // 결과를 담을 배열 선언
    const resultsWithFiles = [];

    for (const row of result) {
      const file_result = await conn.query(file_query, row.File_Key);

      resultsWithFiles.push({
        ...row,
        Total: String(row.Total),
        Idx: row.Idx,
        Board_Type: row.Board_Type,
        Subject: row.Subject,
        Contents: row.Contents,
        File_Key: row.File_Key,
        Visited: row.Visited,
        InDate: row.InDate,
        Unit: row.Unit,
        Images: file_result,
      });
    }
    res.json({
      RET_DATA: { resultsWithFiles },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Picture List End
//=============================================================

//=============================================================
// Picture View Start
app.post("/User/Picture_View", async (req, res) => {
  const { Board_Type, Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    // 게시물 조회
    const query = `Select (
          SELECT CAST(COUNT(Idx) AS UNSIGNED) 
          FROM NKSSA_Board 
          WHERE Board_Type = ?
      ) AS Total, Idx, Board_Type, Subject, Contents, File_Key, Visited, InDate, Unit From NKSSA_Picture Where Idx = ?`;
    const result = await conn.query(query, [Board_Type, Idx]);

    // 파일 조회
    const file_query = `Select File_Path From NKSSA_FileAttach Where File_Key = ?`;
    const file_result = await conn.query(file_query, [result[0].File_Key]);
    res.json({
      RET_DATA: { result, file_result },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Picture View End
//=============================================================

//=============================================================
// Calender List Start
app.post("/User/Calender_List", async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, Edu_State, InDate From NKSSA_Calender";
    const result = await conn.query(query, []);
    res.json({
      RET_DATA: result,
      RET_DESC: "조회 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender List End
//=============================================================

//=============================================================
// Calender View Start
app.post("/User/Calender_View", async (req, res) => {
  const { Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, Edu_State, InDate From NKSSA_Calender Where Idx = ?";
    const result = await conn.query(query, [Idx]);
    res.json({
      RET_DATA: result,
      RET_DESC: "조회 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender View End
//=============================================================

//#############################################################
//######################    USER End   ########################
//#############################################################

// 서버 시작
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

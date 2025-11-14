package com.example.keyboxchecker

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    private lateinit var btnPick: Button
    private lateinit var btnRefresh: Button
    private lateinit var rvCerts: RecyclerView
    private lateinit var tvSummary: TextView
    private lateinit var adapter: CertificateAdapter
    private var lastUri: Uri? = null

    private val pickFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri?.let {
            contentResolver.takePersistableUriPermission(it, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            lastUri = it
            loadAndCheck(it)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnPick = findViewById(R.id.btnPick)
        btnRefresh = findViewById(R.id.btnRefresh)
        rvCerts = findViewById(R.id.rvCerts)
        tvSummary = findViewById(R.id.tvSummary)

        adapter = CertificateAdapter()
        rvCerts.layoutManager = LinearLayoutManager(this)
        rvCerts.adapter = adapter

        btnPick.setOnClickListener {
            pickFile.launch(arrayOf("*/*"))
        }

        btnRefresh.setOnClickListener {
            lastUri?.let { loadAndCheck(it) } ?: Toast.makeText(this, "Pick a keybox.xml first", Toast.LENGTH_SHORT).show()
        }
    }

    private fun loadAndCheck(uri: Uri) {
        btnPick.isEnabled = false
        btnRefresh.isEnabled = false
        tvSummary.text = getString(R.string.checking)

        val handler = CoroutineExceptionHandler { _, e ->
            runOnUiThread {
                Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                btnPick.isEnabled = true
                btnRefresh.isEnabled = true
                tvSummary.text = getString(R.string.weak_integrity)
            }
        }

        lifecycleScope.launch(handler) {
            val (certs, strongIntegrity) = withContext(Dispatchers.IO) {
                KeyboxChecker.checkRevocations(applicationContext, uri)
            }

            adapter.setItems(certs)

            if (strongIntegrity) {
                tvSummary.text = getString(R.string.strong_integrity)
                tvSummary.setBackgroundColor(android.graphics.Color.parseColor("#DFF2E6"))
                tvSummary.setTextColor(android.graphics.Color.parseColor("#006400"))
            } else {
                tvSummary.text = getString(R.string.weak_integrity)
                tvSummary.setBackgroundColor(android.graphics.Color.parseColor("#FFE6E6"))
                tvSummary.setTextColor(android.graphics.Color.parseColor("#800000"))
            }

            btnPick.isEnabled = true
            btnRefresh.isEnabled = true
        }
    }
}
